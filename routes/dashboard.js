const express = require('express');
const multer = require('multer');
const { ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getDB } = require('../config/db');
const { authMiddleware } = require('../middleware/auth');
const { presignedUrl } = require('../config/s3');
const { useConfirmedPriceAuthority } = require('../config/pricing');
const { resolveConfirmedPriceForApi } = require('../lib/orderPricing');

const router = express.Router();

const reportUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(pdf|png|jpg|jpeg)$/i.test(file.originalname || '');
    cb(null, ok);
  },
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-secret-please-change';
const DASHBOARD_SECRET = process.env.DASHBOARD_SECRET || '';
const ACCESS_EXPIRES = process.env.JWT_ACCESS_EXPIRES || '30d';
const BANNER_CACHE_META_KEY = 'banner_cache_meta';

function requireDashboard(req, res, next) {
  if (!req.isDashboard && !req.isAdmin) return res.status(403).json({ error: 'Dashboard access required' });
  next();
}

async function bumpBannerCacheVersion(db) {
  const now = new Date();
  await db.collection('content').updateOne(
    { key: BANNER_CACHE_META_KEY },
    {
      $set: {
        value: { version: String(now.getTime()), updatedAt: now.toISOString() },
        updatedAt: now,
      },
      $setOnInsert: { createdAt: now },
    },
    { upsert: true },
  );
}

// ──────────────────────────────────────────────
// AUTH (no JWT required — dashboard key protects these)
// ──────────────────────────────────────────────

router.post('/login', async (req, res) => {
  try {
    const dashKey = req.headers['x-dashboard-key'];
    if (!DASHBOARD_SECRET || dashKey !== DASHBOARD_SECRET) {
      return res.status(403).json({ error: 'Invalid dashboard key' });
    }
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    const db = getDB();
    const admin = await db.collection('admin_users').findOne({ email: email.trim().toLowerCase() });
    if (!admin || admin.status !== 'Active') {
      return res.status(401).json({ error: 'Invalid credentials or account inactive' });
    }
    const valid = await bcrypt.compare(password, admin.passwordHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials or account inactive' });
    }
    const token = jwt.sign({ adminId: String(admin._id), type: 'admin', role: admin.role }, JWT_SECRET, { expiresIn: ACCESS_EXPIRES });
    res.json({
      token,
      admin: { id: String(admin._id), name: admin.name, email: admin.email, role: admin.role },
    });
  } catch (err) {
    console.error('Dashboard POST /login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

router.get('/me', authMiddleware, requireDashboard, async (req, res) => {
  try {
    if (!req.isAdmin) return res.status(403).json({ error: 'Admin token required' });
    const db = getDB();
    const admin = await db.collection('admin_users').findOne({ _id: new ObjectId(req.user.id) });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    res.json({ id: String(admin._id), name: admin.name, email: admin.email, role: admin.role });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

/** PATCH display name and/or email for the logged-in admin (persisted to MongoDB). */
router.patch('/me', authMiddleware, requireDashboard, async (req, res) => {
  try {
    if (!req.isAdmin) return res.status(403).json({ error: 'Admin token required' });
    const { name, email } = req.body || {};
    const db = getDB();
    const adminId = new ObjectId(req.user.id);
    const updates = {};
    if (name !== undefined) {
      const n = String(name).trim();
      if (!n) return res.status(400).json({ error: 'Name cannot be empty' });
      updates.name = n;
    }
    if (email !== undefined) {
      const em = String(email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) {
        return res.status(400).json({ error: 'Invalid email address' });
      }
      const taken = await db.collection('admin_users').findOne({ email: em, _id: { $ne: adminId } });
      if (taken) return res.status(409).json({ error: 'Email is already in use by another admin' });
      updates.email = em;
    }
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No changes provided' });
    }
    updates.updatedAt = new Date();
    await db.collection('admin_users').updateOne({ _id: adminId }, { $set: updates });
    const admin = await db.collection('admin_users').findOne({ _id: adminId });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    res.json({ id: String(admin._id), name: admin.name, email: admin.email, role: admin.role });
  } catch (err) {
    console.error('Dashboard PATCH /me error:', err);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

/** Change password for the logged-in admin. Uses 400 (not 401) on wrong current password so clients do not treat it as session expiry. */
router.patch('/me/password', authMiddleware, requireDashboard, async (req, res) => {
  try {
    if (!req.isAdmin) return res.status(403).json({ error: 'Admin token required' });
    const { currentPassword, newPassword } = req.body || {};
    if (currentPassword == null || String(currentPassword).length === 0) {
      return res.status(400).json({ error: 'Current password is required' });
    }
    if (newPassword == null || typeof newPassword !== 'string') {
      return res.status(400).json({ error: 'New password is required' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }
    const db = getDB();
    const adminId = new ObjectId(req.user.id);
    const admin = await db.collection('admin_users').findOne({ _id: adminId });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    const valid = await bcrypt.compare(String(currentPassword), admin.passwordHash);
    if (!valid) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    const passwordHash = await bcrypt.hash(newPassword, 10);
    await db.collection('admin_users').updateOne({ _id: adminId }, { $set: { passwordHash, updatedAt: new Date() } });
    res.json({ ok: true });
  } catch (err) {
    console.error('Dashboard PATCH /me/password error:', err);
    res.status(500).json({ error: 'Failed to update password' });
  }
});

router.post('/seed-admins', async (req, res) => {
  try {
    const dashKey = req.headers['x-dashboard-key'];
    if (!DASHBOARD_SECRET || dashKey !== DASHBOARD_SECRET) {
      return res.status(403).json({ error: 'Invalid dashboard key' });
    }
    const db = getDB();
    const existing = await db.collection('admin_users').countDocuments({});
    if (existing > 0) {
      return res.json({ message: `Already seeded (${existing} admins exist)`, seeded: false });
    }
    const hash = await bcrypt.hash('demo123', 10);
    const admins = [
      { name: 'Admin', email: 'admin@mineralbridge.com', passwordHash: hash, role: 'ceo', status: 'Active', createdAt: new Date() },
      { name: 'Sarah Connor', email: 'sarah@mineralbridge.com', passwordHash: hash, role: 'ceo', status: 'Active', createdAt: new Date() },
      { name: 'John Smith', email: 'john@mineralbridge.com', passwordHash: hash, role: 'operations_manager', status: 'Active', createdAt: new Date() },
      { name: 'Emily Chen', email: 'emily@mineralbridge.com', passwordHash: hash, role: 'support_agent', status: 'Inactive', createdAt: new Date() },
    ];
    const result = await db.collection('admin_users').insertMany(admins);
    res.json({ message: `Seeded ${result.insertedCount} admin(s)`, seeded: true });
  } catch (err) {
    console.error('Dashboard POST /seed-admins error:', err);
    res.status(500).json({ error: 'Seed failed' });
  }
});

/** Restore CEO demo login after a new Mongo URI / empty admin_users / wrong password hash. Same key as login. */
router.post('/upsert-demo-admin', async (req, res) => {
  try {
    const dashKey = req.headers['x-dashboard-key'];
    if (!DASHBOARD_SECRET || dashKey !== DASHBOARD_SECRET) {
      return res.status(403).json({ error: 'Invalid dashboard key' });
    }
    const db = getDB();
    const email = 'admin@mineralbridge.com';
    const hash = await bcrypt.hash('demo123', 10);
    const now = new Date();
    const r = await db.collection('admin_users').updateOne(
      { email },
      {
        $set: {
          name: 'Admin',
          email,
          passwordHash: hash,
          role: 'ceo',
          status: 'Active',
          updatedAt: now,
        },
        $setOnInsert: { createdAt: now },
      },
      { upsert: true },
    );
    res.json({
      ok: true,
      email,
      upserted: r.upsertedCount === 1,
      modified: r.modifiedCount === 1,
      matched: r.matchedCount,
    });
  } catch (err) {
    console.error('Dashboard POST /upsert-demo-admin error:', err);
    res.status(500).json({ error: 'Upsert failed' });
  }
});

// ──────────────────────────────────────────────
// USERS
// ──────────────────────────────────────────────

/** Dial codes → country name for user list and detail (dashboard). */
const DIAL_TO_COUNTRY_USERS = {
  '+233': 'Ghana', '+234': 'Nigeria', '+255': 'Tanzania', '+243': 'DRC', '+260': 'Zambia',
  '+263': 'Zimbabwe', '+254': 'Kenya', '+256': 'Uganda', '+223': 'Mali', '+226': 'Burkina Faso',
  '+27': 'South Africa', '+91': 'India', '+1': 'United States', '+44': 'United Kingdom',
  '+41': 'Switzerland', '+49': 'Germany', '+33': 'France', '+81': 'Japan', '+86': 'China',
  '+237': 'Cameroon', '+251': 'Ethiopia', '+221': 'Senegal',
};

function dialToCountryName(countryCode) {
  if (!countryCode) return null;
  const dial = String(countryCode).trim().startsWith('+') ? countryCode : `+${countryCode}`;
  return DIAL_TO_COUNTRY_USERS[dial] || null;
}

router.get('/users', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const skip = parseInt(req.query.skip, 10) || 0;
    const users = await db.collection('users').find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray();
    const profiles = await db.collection('profiles').find({}).toArray();
    const profileMap = {};
    profiles.forEach((p) => { profileMap[p.userId] = p; });
    const total = await db.collection('users').countDocuments({});
    const usersWithAvatars = await Promise.all(users.map(async (u) => {
      const profile = profileMap[u._id.toString()];
      const countryName = dialToCountryName(u.countryCode);
      let avatarUrl = profile?.avatarUrl || null;
      if (!avatarUrl && profile?.avatarKey) {
        try {
          avatarUrl = await presignedUrl(profile.avatarKey);
        } catch (e) {
          console.warn('Avatar presign error for user', u._id, e.message);
        }
      }
      return {
        id: u._id.toString(),
        phone: u.phone,
        countryCode: u.countryCode,
        country: countryName || undefined,
        name: u.name,
        email: u.email,
        kycStatus: profile?.kycStatus || 'pending',
        avatarUrl,
        twoFactorEnabled: profile?.twoFactorEnabled || false,
        lastLocation: u.lastLocation || null,
        createdAt: u.createdAt,
        riskLevel: profile?.riskLevel || null,
        operationalType: profile?.operationalType || null,
        verificationSource: profile?.verificationSource || null,
        lastReviewedBy: profile?.lastReviewedBy || null,
        lastReviewedAt: profile?.lastReviewedAt || null,
      };
    }));
    res.json({ total, users: usersWithAvatars });
  } catch (err) {
    console.error('Dashboard GET /users error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/users/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.params.id) });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const profile = await db.collection('profiles').findOne({ userId: req.params.id });
    let avatarUrl = profile?.avatarUrl || null;
    if (!avatarUrl && profile?.avatarKey) {
      try {
        avatarUrl = await presignedUrl(profile.avatarKey);
      } catch (e) {
        console.warn('Avatar presign error:', e.message);
      }
    }
    const countryName = dialToCountryName(user.countryCode);
    res.json({
      id: user._id.toString(),
      phone: user.phone,
      countryCode: user.countryCode,
      country: countryName || undefined,
      name: user.name,
      email: user.email,
      kycStatus: profile?.kycStatus || 'pending',
      avatarUrl,
      twoFactorEnabled: profile?.twoFactorEnabled || false,
      lastLocation: user.lastLocation || null,
      createdAt: user.createdAt,
      operationalType: profile?.operationalType || null,
      riskLevel: profile?.riskLevel || null,
      verificationSource: profile?.verificationSource || null,
      lastReviewedBy: profile?.lastReviewedBy || null,
      lastReviewedAt: profile?.lastReviewedAt || null,
      kycRejectionReason: profile?.kycRejectionReason || null,
    });
  } catch (err) {
    console.error('Dashboard GET /users/:id error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/**
 * DELETE /api/dashboard/users/:id
 * Permanently delete a user and all their data from the database.
 */
router.delete('/users/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid user id' });
    let oid;
    try {
      oid = new ObjectId(id);
    } catch (_) {
      return res.status(400).json({ error: 'Invalid user id' });
    }
    const db = getDB();
    const uid = String(id);
    const user = await db.collection('users').findOne({ _id: oid });
    if (!user) {
      await db.collection('account_deletions').deleteMany({ $or: [{ userId: uid }, { userId: oid }] });
      return res.json({ success: true, deleted: true, alreadyDeleted: true });
    }

    const profile = await db.collection('profiles').findOne({ userId: uid });
    const now = new Date();
    const deletionRecord = {
      type: 'admin_deleted',
      userId: uid,
      userName: user.name || profile?.name || '',
      userEmail: user.email || profile?.email || '',
      userPhone: user.phone || '',
      status: 'completed',
      deletedBy: req.user.id,
      deletedByName: req.user.name || 'Admin',
      deletedAt: now,
      createdAt: now,
      reason: 'Deleted from User Management',
    };

    await db.collection('account_deletions').deleteMany({ $or: [{ userId: uid }, { userId: oid }] });
    try {
      await db.collection('account_deletions').insertOne(deletionRecord);
    } catch (insErr) {
      if (insErr && insErr.code === 11000) {
        console.warn('Delete user: account_deletions audit insert duplicate, continuing');
      } else {
        throw insErr;
      }
    }

    const idFilter = { $or: [{ userId: uid }, { userId: oid }] };

    const collectionsWithUserId = [
      'profiles',
      'addresses',
      'payment_methods',
      'kyc_documents',
      'kyc_document_requests',
      'notifications',
      'push_tokens',
      'user_sessions',
      'activity',
      'activity_feed',
      'app_settings',
      'security_alerts',
      'user_cache',
      'draft_orders',
      'support_requests',
    ];
    for (const col of collectionsWithUserId) {
      try {
        await db.collection(col).deleteMany(idFilter);
      } catch (e) {
        console.warn(`Delete user: ${col} error:`, e.message);
      }
    }
    await db.collection('transactions').deleteMany(idFilter);
    await db.collection('orders').deleteMany(idFilter);
    await db.collection('listings').deleteMany(idFilter);
    await db.collection('callbacks').deleteMany({ userId: uid });
    await db.collection('scheduled_calls').deleteMany({ userId: uid });
    await db.collection('login_history').deleteMany({ userId: uid });
    await db.collection('chat_messages').deleteMany({ senderId: uid });
    try {
      await db.collection('call_history').deleteMany(idFilter);
    } catch (_) {}
    const refreshCol = db.collection('refresh_tokens');
    try {
      await refreshCol.deleteMany({ userId: uid });
    } catch (_) {}
    const artisanalCols = ['artisanal_profiles', 'certifications', 'equipment_requests', 'incident_reports', 'safety_training'];
    for (const col of artisanalCols) {
      try {
        await db.collection(col).deleteMany(idFilter);
      } catch (_) {}
    }
    await db.collection('users').deleteOne({ _id: oid });
    res.json({ success: true, deleted: true });
  } catch (err) {
    console.error('Dashboard DELETE /users/:id error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

router.patch('/users/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { name, email, kycStatus, kycRejectionReason, operationalType, riskLevel, verificationSource } = req.body || {};
    const db = getDB();
    const userUpdates = {};
    if (name !== undefined) userUpdates.name = name;
    if (email !== undefined) userUpdates.email = email;
    if (Object.keys(userUpdates).length > 0) {
      await db.collection('users').updateOne({ _id: new ObjectId(req.params.id) }, { $set: userUpdates });
    }
    const profileUpdates = { updatedAt: new Date() };
    if (kycStatus !== undefined) profileUpdates.kycStatus = kycStatus;
    if (kycRejectionReason !== undefined) profileUpdates.kycRejectionReason = kycRejectionReason;
    if (operationalType !== undefined) profileUpdates.operationalType = operationalType;
    if (riskLevel !== undefined) profileUpdates.riskLevel = riskLevel;
    if (verificationSource !== undefined) profileUpdates.verificationSource = verificationSource;
    if (kycStatus === 'approved' || kycStatus === 'rejected') {
      profileUpdates.lastReviewedBy = req.user?.name || req.user?.email || 'Admin';
      profileUpdates.lastReviewedAt = new Date();
      if (kycStatus === 'rejected' && kycRejectionReason !== undefined) profileUpdates.kycRejectionReason = kycRejectionReason;
    }
    if (Object.keys(profileUpdates).length > 1) {
      await db.collection('profiles').updateOne(
        { userId: req.params.id },
        { $set: profileUpdates },
        { upsert: true },
      );
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Dashboard PATCH /users/:id error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/**
 * POST /api/dashboard/users/:userId/kyc-document-requests
 * Request additional KYC document(s) from the user. Stores the request and optionally notifies the user.
 * Body: { message, documentType? }
 */
router.post('/users/:userId/kyc-document-requests', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { userId } = req.params;
    const { message, documentType } = req.body || {};
    if (!message || typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: 'message required' });
    }
    const db = getDB();
    const doc = {
      userId: String(userId),
      message: message.trim(),
      documentType: documentType && String(documentType).trim() ? String(documentType).trim() : null,
      status: 'pending',
      requestedBy: req.user?.name || req.user?.email || 'Admin',
      requestedAt: new Date(),
      createdAt: new Date(),
    };
    const result = await db.collection('kyc_document_requests').insertOne(doc);
    const requestId = result.insertedId.toString();
    const tokens = await db.collection('push_tokens').find({ userId: String(userId) }).toArray();
    const expoTokens = tokens.map((t) => t.expoPushToken).filter(Boolean);
    if (expoTokens.length > 0) {
      const { sendExpoPush } = require('../lib/pushNotifications');
      sendExpoPush(expoTokens, {
        title: 'Document request from Mineral Bridge',
        body: message.trim().slice(0, 120) + (message.trim().length > 120 ? '…' : ''),
        data: { type: 'kyc_document_request', requestId },
      }).catch(() => {});
    }
    res.status(201).json({
      id: requestId,
      userId: doc.userId,
      message: doc.message,
      documentType: doc.documentType,
      status: doc.status,
      requestedBy: doc.requestedBy,
      requestedAt: doc.requestedAt,
    });
  } catch (err) {
    console.error('Dashboard POST /users/:userId/kyc-document-requests error:', err);
    res.status(500).json({ error: 'Failed to create document request' });
  }
});

/**
 * POST /api/dashboard/users/:userId/send-notification
 * Send a push notification and/or email to a specific app user (e.g. video call link from User Management).
 * Body: { title, body?, data?, channel: "app"|"email", link? }
 * - channel "app": sends Expo push notification
 * - channel "email": sends email via Resend (requires RESEND_API_KEY and user email)
 */
router.post('/users/:userId/send-notification', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { userId } = req.params;
    const { title, body, data, channel = 'app', link } = req.body || {};
    if (!title) return res.status(400).json({ error: 'title required' });
    const db = getDB();
    let pushSent = false;
    let emailSent = false;

    if (channel === 'app' || !channel) {
      const tokens = await db.collection('push_tokens').find({ userId: String(userId) }).toArray();
      const expoTokens = tokens.map((t) => t.expoPushToken).filter(Boolean);
      const { sendExpoPush } = require('../lib/pushNotifications');
      sendExpoPush(expoTokens, {
        title: title || 'Mineral Bridge',
        body: body || '',
        data: data || {},
      }).catch(() => {});
      pushSent = expoTokens.length > 0;
    }

    if (channel === 'email') {
      if (!process.env.RESEND_API_KEY) {
        return res.status(503).json({ error: 'Email not configured', message: 'RESEND_API_KEY is not set. Add it to backend .env to send emails.' });
      }
      const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
      const profile = await db.collection('profiles').findOne({ userId: String(userId) });
      const toEmail = user?.email || profile?.email;
      if (!toEmail) {
        return res.status(400).json({ error: 'No email', message: 'User has no email address. Add email to user or profile.' });
      }
      try {
        const { Resend } = require('resend');
        const resend = new Resend(process.env.RESEND_API_KEY);
        const subject = title;
        const linkHtml = link ? `<p><a href="${link}" style="color:#059669;font-weight:600">Click here to join</a></p><p style="word-break:break-all;color:#64748b;">${link}</p>` : '';
        const htmlBody = `<p>${body || 'You have a new message from Mineral Bridge.'}</p>${linkHtml}`;
        const result = await resend.emails.send({
          from: process.env.RESEND_FROM || 'Mineral Bridge <onboarding@resend.dev>',
          to: toEmail,
          subject,
          html: htmlBody,
        });
        if (result?.error) {
          console.warn('Resend email error:', result.error);
          return res.status(500).json({ error: 'Email failed', message: result.error.message || 'Resend rejected the email.' });
        }
        emailSent = true;
      } catch (e) {
        console.error('Resend email failed:', e);
        return res.status(500).json({ error: 'Email failed', message: e.message || 'Could not send email.' });
      }
    }

    const notif = {
      userId: String(userId),
      title: title || 'Mineral Bridge',
      body: body || '',
      data: data || {},
      channel: channel || 'app',
      createdAt: new Date(),
    };
    await db.collection('notifications').insertOne(notif);
    res.json({ success: true, sent: pushSent || emailSent, emailSent, pushSent });
  } catch (err) {
    console.error('Dashboard POST /users/:userId/send-notification error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// ADDRESSES (for a specific user)
// ──────────────────────────────────────────────

router.get('/users/:id/addresses', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('addresses').find({ userId: req.params.id }).sort({ createdAt: -1 }).toArray();
    res.json(list.map((a) => ({ id: a._id.toString(), ...a, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// PAYMENT METHODS (for a specific user)
// ──────────────────────────────────────────────

router.get('/users/:id/payment-methods', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('payment_methods').find({ userId: req.params.id }).sort({ createdAt: -1 }).toArray();
    res.json(list.map((p) => ({
      id: p._id.toString(),
      type: p.type,
      holderName: p.holderName,
      bankName: p.bankName,
      accountNumber: p.accountNumber,
      swift: p.swift,
      label: p.label,
      network: p.network,
      address: p.address,
      verified: p.verified,
      createdAt: p.createdAt,
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/payment-methods/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { verified } = req.body || {};
    const db = getDB();
    const updates = { updatedAt: new Date() };
    if (typeof verified === 'boolean') updates.verified = verified;
    await db.collection('payment_methods').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// ARTISANAL PROFILES
// ──────────────────────────────────────────────

router.get('/artisanal-profiles', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('artisanal_profiles').find({}).sort({ createdAt: -1 }).limit(100).toArray();
    res.json(list.map((p) => ({ id: p._id.toString(), ...p, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/users/:id/artisanal-profile', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const profile = await db.collection('artisanal_profiles').findOne({ userId: req.params.id });
    if (!profile) return res.status(404).json({ error: 'Not found' });
    res.json({ id: profile._id.toString(), ...profile, _id: undefined });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/artisanal-profiles/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const updates = { ...req.body, updatedAt: new Date() };
    delete updates._id;
    delete updates.id;
    const db = getDB();
    await db.collection('artisanal_profiles').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// Dashboard: fetch artisanal equipment requests, incident reports, certifications, safety-training by userId (same data app stores)
router.get('/users/:id/artisanal-equipment-requests', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const uid = String(req.params.id);
    const list = await db.collection('equipment_requests').find({ userId: uid }).sort({ requestedAt: -1 }).limit(50).toArray();
    res.json(list.map((r) => ({ id: r._id.toString(), itemName: r.itemName, status: r.status, requestedAt: r.requestedAt, tier: r.tier, creditRatio: r.creditRatio })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/users/:id/artisanal-incident-reports', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const uid = String(req.params.id);
    const list = await db.collection('incident_reports').find({ userId: uid }).sort({ createdAt: -1 }).limit(50).toArray();
    res.json(list.map((r) => ({ id: r._id.toString(), category: r.category, categoryDisplay: r.categoryDisplay, description: r.description, photoUrl: r.photoUrl, status: r.status, dispatchedAt: r.dispatchedAt, createdAt: r.createdAt })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/users/:id/artisanal-certifications', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const uid = String(req.params.id);
    const doc = await db.collection('certifications').findOne({ userId: uid });
    if (!doc) return res.json(null);
    res.json({ tier: doc.tier, blockchainHash: doc.blockchainHash, gpsAnchored: doc.gpsAnchored, l1Accredited: doc.l1Accredited, pdfUrl: doc.pdfUrl, updatedAt: doc.updatedAt });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/users/:id/artisanal-safety-training', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const uid = String(req.params.id);
    const doc = await db.collection('safety_training').findOne({ userId: uid });
    if (!doc) return res.json({ modules: [], updatedAt: null });
    res.json({ modules: doc.modules || [], updatedAt: doc.updatedAt });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// ORDERS (all users)
// ──────────────────────────────────────────────

/** Dial codes → country name for seller country fallback */
const DIAL_TO_COUNTRY = {
  '+233': 'Ghana', '+234': 'Nigeria', '+255': 'Tanzania', '+243': 'DRC', '+260': 'Zambia',
  '+263': 'Zimbabwe', '+254': 'Kenya', '+256': 'Uganda', '+223': 'Mali', '+226': 'Burkina Faso',
  '+27': 'South Africa', '+91': 'India', '+1': 'United States', '+44': 'United Kingdom',
  '+41': 'Switzerland', '+49': 'Germany', '+33': 'France', '+81': 'Japan', '+86': 'China',
};

async function enrichOrderForDashboard(db, rawOrder, cache = null) {
  const o = { id: rawOrder._id.toString(), ...rawOrder, _id: undefined };
  let facility = o.facility;
  let description = o.description;
  let sellerCountry = o.sellerCountry;
  const addrCache = cache?.addresses ?? new Map();
  const userCache = cache?.users ?? new Map();

  // Enrich facility from address
  if (o.addressId && ObjectId.isValid(o.addressId)) {
    let addr = addrCache.get(o.addressId);
    if (!addr) {
      addr = await db.collection('addresses').findOne({ _id: new ObjectId(o.addressId) });
      if (addr) addrCache.set(o.addressId, addr);
    }
    if (addr) {
      const parts = [addr.street, addr.city, addr.state || addr.stateRegion, addr.postalCode, addr.country].filter(Boolean);
      const contactParts = [addr.phone, addr.email].filter(Boolean);
      facility = {
        name: addr.facilityName || addr.label || '—',
        address: parts.join(', ') || '—',
        country: addr.country || '—',
        contact: contactParts.join(' · ') || '—',
      };
      if (!sellerCountry && addr.country) sellerCountry = addr.country;
    }
  }

  // Fallback seller country from user
  if (!sellerCountry && o.userId && ObjectId.isValid(o.userId)) {
    let user = userCache.get(o.userId);
    if (!user) {
      user = await db.collection('users').findOne({ _id: new ObjectId(o.userId) });
      if (user) userCache.set(o.userId, user);
    }
    if (user?.countryCode) {
      const dial = String(user.countryCode).trim().startsWith('+') ? user.countryCode : `+${user.countryCode}`;
      sellerCountry = DIAL_TO_COUNTRY[dial] || user.countryCode;
    }
  }

  // Build description from mineralType, buyerCategory, mineralName
  if (!description) {
    const parts = [o.mineralType, o.buyerCategory, o.mineralName].filter(Boolean);
    description = parts.map((p) => String(p).trim()).join(' — ') || o.mineralName || '—';
  }

  return { ...o, facility: facility || { name: '—', address: '—', country: '—', contact: '—' }, description: description || '—', sellerCountry: sellerCountry || null };
}

router.get('/orders', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.type) filter.type = req.query.type;
    if (req.query.status) filter.status = req.query.status;
    if (req.query.userId) filter.userId = req.query.userId;
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const skip = parseInt(req.query.skip, 10) || 0;
    const list = await db.collection('orders').find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray();
    const total = await db.collection('orders').countDocuments(filter);
    const cache = { addresses: new Map(), users: new Map() };
    const orders = await Promise.all(list.map((o) => enrichOrderForDashboard(db, o, cache)));
    res.json({ total, orders });
  } catch (err) {
    console.error('Dashboard GET /orders error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

/** Single order — optional ?forThirdPartyTesting=1 validates Sell + Dashboard Contacted and returns seller snapshot. */
router.get('/orders/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid order id' });
    const db = getDB();
    const raw = await db.collection('orders').findOne({ _id: new ObjectId(id) });
    if (!raw) return res.status(404).json({ error: 'Order not found' });
    const typeNorm = String(raw.type || '').toLowerCase() === 'sell' ? 'Sell' : 'Buy';
    const status = String(raw.status || '').trim();
    if (req.query.forThirdPartyTesting === '1') {
      if (typeNorm !== 'Sell') return res.status(400).json({ error: 'Order must be a Sell order' });
      if (status !== 'Dashboard Contacted') {
        return res.status(400).json({ error: 'Order status must be Dashboard Contacted' });
      }
    }
    let seller = null;
    if (raw.userId && ObjectId.isValid(String(raw.userId))) {
      const u = await db.collection('users').findOne({ _id: new ObjectId(String(raw.userId)) });
      if (u) {
        seller = {
          name: u.name || '—',
          email: u.email || '—',
          phone: u.phone || '—',
        };
      }
    }
    const enriched = await enrichOrderForDashboard(db, raw);
    const siteLocation = enriched.facility?.address || enriched.description || '—';
    res.json({
      ...enriched,
      type: typeNorm,
      seller,
      mineral: raw.mineralName || raw.mineralType || enriched.description || '—',
      quantity: raw.quantity ?? raw.weight ?? raw.amount ?? '—',
      siteLocation,
    });
  } catch (err) {
    console.error('Dashboard GET /orders/:id error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

router.delete('/orders/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid order id' });
    const db = getDB();
    const order = await db.collection('orders').findOne({ _id: new ObjectId(id) });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    await db.collection('orders').deleteOne({ _id: new ObjectId(id) });
    res.json({ success: true });
  } catch (err) {
    console.error('Dashboard DELETE /orders error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/orders/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid order id' });
    const updates = { ...req.body, updatedAt: new Date() };
    delete updates._id;
    delete updates.id;
    if (useConfirmedPriceAuthority()) {
      if (updates.orderSummary && typeof updates.orderSummary === 'object' && updates.orderSummary.total != null) {
        const t = String(updates.orderSummary.total).trim();
        if (t) updates.confirmedPrice = t;
      }
      if (Object.prototype.hasOwnProperty.call(updates, 'confirmedPrice')) {
        const s = updates.confirmedPrice == null ? '' : String(updates.confirmedPrice).trim();
        updates.confirmedPrice = s || null;
      }
    }
    const db = getDB();
    const prevOrder = await db.collection('orders').findOne({ _id: new ObjectId(id) });
    // When dashboard updates flowSteps, sync timeline so app order history shows same flow with dates
    if (Array.isArray(updates.flowSteps) && updates.flowSteps.length > 0) {
      const existingTimeline = Array.isArray(prevOrder?.timeline) ? prevOrder.timeline : [];
      const now = new Date();
      updates.timeline = updates.flowSteps.map((s, i) => {
        const step = i + 1;
        const label = (s && typeof s === 'object' && s.label) ? s.label : `Step ${step}`;
        const existing = existingTimeline.find((t) => t.step === step);
        const at = (existing && existing.at) ? existing.at : now;
        return { step, label, at };
      });
    }
    await db.collection('orders').updateOne({ _id: new ObjectId(id) }, { $set: updates });
    const order = await db.collection('orders').findOne({ _id: new ObjectId(id) });
    if (useConfirmedPriceAuthority() && order) {
      const cp = resolveConfirmedPriceForApi(order);
      if (cp) {
        const num = parseFloat(String(cp).replace(/[^0-9.-]/g, ''));
        const txSet = { updatedAt: new Date() };
        if (Number.isFinite(num)) txSet.total = num;
        await db.collection('transactions').updateMany({ orderId: id }, { $set: txSet }).catch(() => {});
      }
    }
    if (updates.sentToUser && Array.isArray(updates.sentToUser) && updates.sentToUser.length > 0) {
      const prevSent = prevOrder?.sentToUser ?? [];
      const newItems = updates.sentToUser.slice(prevSent.length);
      if (newItems.length > 0 && order?.userId) {
        const { sendExpoPush } = require('../lib/pushNotifications');
        const tokens = await db.collection('push_tokens').find({ userId: String(order.userId) }).toArray();
        const expoTokens = tokens.map((t) => t.expoPushToken).filter(Boolean);
        const typeLabels = { qr_or_bank: 'Bank/QR', transport_link: 'Logistics link', sample_pickup_link: 'Sample pickup', lc_credit: 'LC/Credit', testing_certificate: 'Testing cert', lab_report: 'Lab report' };
        for (let idx = 0; idx < newItems.length; idx++) {
          const item = newItems[idx];
          const typeLabel = typeLabels[item.type] || item.type || 'Link';
          const title = `${typeLabel}: ${item.label || 'New link'}`;
          const body = item.detail || item.label || 'Tap to view';
          const sentIndex = prevSent.length + idx;
          sendExpoPush(expoTokens, { title, body, data: { orderId: id, type: 'sentToUser', label: item.label, detail: item.detail, linkType: item.type, sentIndex, channel: item.channel || 'App' } }).catch(() => {});
          const notif = {
            userId: String(order.userId),
            title,
            body,
            data: { orderId: id, linkType: item.type, detail: item.detail, label: item.label, sentIndex, channel: item.channel || 'App' },
            createdAt: new Date(),
          };
          await db.collection('notifications').insertOne(notif);
        }
      }
    }
    const enriched = await enrichOrderForDashboard(db, order);
    res.json(enriched);
  } catch (err) {
    console.error('Dashboard PATCH /orders error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// TRANSACTIONS (all users)
// ──────────────────────────────────────────────

router.get('/transactions', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.userId) filter.userId = req.query.userId;
    if (req.query.type) filter.type = req.query.type;
    if (req.query.status) filter.status = req.query.status;
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const list = await db.collection('transactions').find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
    const total = await db.collection('transactions').countDocuments(filter);
    res.json({ total, transactions: list.map((t) => ({ id: t._id.toString(), ...t, _id: undefined })) });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// MINERALS – BULK CLEAN (from app)
// ──────────────────────────────────────────────

// Clear subProductDescription and set verificationStatus=Verified for minerals that appear in
// Buy Management → Buy list (from app). We treat "from app" as minerals that are availableForBuy=true.
router.patch('/minerals/bulk-clean-from-app', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = { availableForBuy: { $ne: false } };
    const update = {
      $set: {
        verificationStatus: 'Verified',
        subProductDescription: '',
      },
    };
    const result = await db.collection('minerals').updateMany(filter, update);
    res.json({
      success: true,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
    });
  } catch (err) {
    console.error('Dashboard PATCH /minerals/bulk-clean-from-app error:', err);
    res.status(500).json({ error: 'Failed to bulk update minerals' });
  }
});

/** Last uploaded Mineral Bridge master sheet (.xlsx) — S3 key stored after successful import + upload. */
const MASTER_SHEET_CATALOG_CONTENT_KEY = 'master_sheet_catalog_upload';

// Body: { s3Key, fileName } — called after POST /api/upload archives the workbook.
router.post('/catalog/master-sheet-meta', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const s3Key = req.body && String(req.body.s3Key || '').trim();
    const fileName = req.body && String(req.body.fileName || '').trim();
    if (!s3Key) return res.status(400).json({ error: 's3Key is required' });
    const db = getDB();
    const now = new Date();
    await db.collection('content').updateOne(
      { key: MASTER_SHEET_CATALOG_CONTENT_KEY },
      {
        $set: {
          key: MASTER_SHEET_CATALOG_CONTENT_KEY,
          value: {
            s3Key,
            fileName: fileName || 'master-sheet.xlsx',
            updatedAt: now.toISOString(),
          },
          updatedAt: now,
        },
        $setOnInsert: { createdAt: now },
      },
      { upsert: true },
    );
    res.json({ success: true });
  } catch (err) {
    console.error('Dashboard POST /catalog/master-sheet-meta error:', err);
    res.status(500).json({ error: 'Failed to save master sheet reference' });
  }
});

router.get('/catalog/master-sheet-download', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const doc = await db.collection('content').findOne({ key: MASTER_SHEET_CATALOG_CONTENT_KEY });
    const s3Key = doc && doc.value && doc.value.s3Key;
    if (!s3Key) {
      return res.status(404).json({
        error: 'No master sheet on file yet. Import from master sheet once to archive the workbook.',
      });
    }
    const url = await presignedUrl(s3Key, { scope: 'admin', expiresIn: 3600 });
    res.json({
      url,
      fileName: (doc.value && doc.value.fileName) || 'master-sheet.xlsx',
      updatedAt: doc.value && doc.value.updatedAt,
    });
  } catch (err) {
    console.error('Dashboard GET /catalog/master-sheet-download error:', err);
    res.status(500).json({ error: 'Failed to generate download link' });
  }
});

// Create a new transaction (e.g. when user pays via QR link sent from dashboard)
router.post('/transactions', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const body = req.body || {};
    const orderId = body.orderId;
    if (!orderId || !ObjectId.isValid(orderId)) return res.status(400).json({ error: 'Valid orderId required' });

    const order = await db.collection('orders').findOne({ _id: new ObjectId(orderId) });
    if (!order) return res.status(404).json({ error: 'Order not found' });

    const now = new Date();
    const dateStr = body.date || now.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
    const timeStr = body.time || now.toTimeString().slice(0, 5);

    const doc = {
      orderId: String(orderId),
      userId: body.userId ?? order.userId ?? undefined,
      type: body.orderType ?? order.type ?? 'Buy',
      orderType: body.orderType ?? order.type ?? 'Buy',
      mineral: body.mineral ?? order.mineralName ?? order.mineral ?? '—',
      aiEstimate: body.aiEstimate ?? order.totalDue ?? order.amount ?? order.aiEstimatedAmount ?? '$0',
      finalAmount: body.finalAmount ?? body.total ?? order.totalDue ?? order.amount ?? order.aiEstimatedAmount ?? '$0',
      serviceFee: body.serviceFee ?? '$0',
      netAmount: body.netAmount ?? body.finalAmount ?? body.total ?? order.totalDue ?? order.amount ?? '$0',
      currency: body.currency ?? order.currency ?? 'USD',
      method: body.method ?? 'Bank Transfer',
      status: body.status ?? 'Completed',
      date: dateStr,
      time: timeStr,
      paymentDetails: body.paymentDetails || {},
      settlementNote: body.settlementNote || '',
      adminNotes: body.adminNotes || [],
      createdAt: now,
      updatedAt: now,
    };
    if (body.paymentChannel) doc.paymentChannel = body.paymentChannel;
    if (body.payerCountry) doc.payerCountry = body.payerCountry;
    if (body.beneficiaryCountry) doc.beneficiaryCountry = body.beneficiaryCountry;
    if (body.reference) doc.reference = body.reference;

    const result = await db.collection('transactions').insertOne(doc);
    const inserted = await db.collection('transactions').findOne({ _id: result.insertedId });
    const out = { id: inserted._id.toString(), ...inserted, _id: undefined };
    res.status(201).json(out);
  } catch (err) {
    console.error('Dashboard POST /transactions error:', err);
    res.status(500).json({ error: 'Failed to create transaction' });
  }
});

router.patch('/transactions/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid transaction id' });
    const updates = { ...req.body, updatedAt: new Date() };
    delete updates._id;
    delete updates.id;
    const db = getDB();
    await db.collection('transactions').updateOne({ _id: new ObjectId(id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// PAYOUTS (settlement batches; optional collection)
// ──────────────────────────────────────────────

router.get('/payouts', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('payouts').find({}).sort({ date: -1 }).limit(200).toArray();
    const payouts = list.map((p) => ({
      id: p._id ? p._id.toString() : p.id,
      label: p.label || '',
      date: p.date || p.createdAt,
      totalAmount: p.totalAmount ?? 0,
      currency: p.currency || 'USD',
      transactionCount: p.transactionCount ?? 0,
      status: p.status || 'Settled',
    }));
    res.json(payouts);
  } catch (err) {
    if (err.code === 'NamespaceNotFound' || err.message && err.message.includes('payouts')) {
      return res.json([]);
    }
    console.error('Dashboard GET /payouts error:', err);
    res.json([]);
  }
});

// ──────────────────────────────────────────────
// KYC DOCUMENTS (all users)
// ──────────────────────────────────────────────

router.get('/kyc', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.userId) filter.userId = req.query.userId;
    if (req.query.status) filter.status = req.query.status;
    const list = await db.collection('kyc_documents').find(filter).sort({ createdAt: -1 }).limit(100).toArray();
    const withUrls = await Promise.all(list.map(async (d) => {
      let frontUrl = null, backUrl = null, selfieUrl = null;
      try {
        if (d.frontKey) frontUrl = await presignedUrl(d.frontKey);
        else if (d.frontUrl && typeof d.frontUrl === 'string') frontUrl = d.frontUrl;
        if (d.backKey) backUrl = await presignedUrl(d.backKey);
        else if (d.backUrl && typeof d.backUrl === 'string') backUrl = d.backUrl;
        if (d.selfieKey) selfieUrl = await presignedUrl(d.selfieKey);
        else if (d.selfieUrl && typeof d.selfieUrl === 'string') selfieUrl = d.selfieUrl;
      } catch (e) {
        console.warn('KYC presign error:', e.message);
      }
      return {
        id: d._id.toString(),
        userId: d.userId,
        idType: d.idType,
        status: d.status,
        createdAt: d.createdAt,
        frontUrl,
        backUrl,
        selfieUrl,
      };
    }));
    res.json(withUrls);
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/kyc/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { status } = req.body || {};
    if (!status) return res.status(400).json({ error: 'status required' });
    const db = getDB();
    await db.collection('kyc_documents').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status, updatedAt: new Date() } },
    );
    const doc = await db.collection('kyc_documents').findOne({ _id: new ObjectId(req.params.id) });
    if (doc) {
      await db.collection('profiles').updateOne(
        { userId: doc.userId },
        { $set: { kycStatus: status, updatedAt: new Date() } },
        { upsert: true },
      );
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// SECURITY ALERTS (all users)
// ──────────────────────────────────────────────

router.get('/security-alerts', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.userId) filter.userId = req.query.userId;
    const list = await db.collection('security_alerts').find(filter).sort({ createdAt: -1 }).limit(100).toArray();
    res.json(list.map((a) => ({ id: a._id.toString(), ...a, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// APP SETTINGS (all users)
// ──────────────────────────────────────────────

router.get('/app-settings', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.userId) filter.userId = req.query.userId;
    const list = await db.collection('app_settings').find(filter).sort({ updatedAt: -1 }).limit(100).toArray();
    res.json(list.map((s) => ({ id: s._id.toString(), ...s, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// CALLBACKS (all)
// ──────────────────────────────────────────────

router.get('/callbacks', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    const list = await db.collection('callbacks').find(filter).sort({ createdAt: -1 }).limit(100).toArray();
    res.json(list.map((c) => ({ id: c._id.toString(), ...c, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/callbacks/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { status } = req.body || {};
    if (!status) return res.status(400).json({ error: 'status required' });
    const db = getDB();
    await db.collection('callbacks').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status, updatedAt: new Date() } },
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// CHAT MESSAGES (all conversations)
// ──────────────────────────────────────────────

router.get('/chats', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const pipeline = [
      { $group: { _id: '$orderId', lastMessage: { $last: '$$ROOT' }, count: { $sum: 1 } } },
      { $sort: { 'lastMessage.createdAt': -1 } },
      { $limit: 100 },
    ];
    const convos = await db.collection('chat_messages').aggregate(pipeline).toArray();
    res.json(convos.map((c) => ({
      orderId: c._id,
      messageCount: c.count,
      lastSender: c.lastMessage.senderName,
      lastText: c.lastMessage.text,
      lastAt: c.lastMessage.createdAt,
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/chats/:orderId', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const messages = await db.collection('chat_messages')
      .find({ orderId: req.params.orderId })
      .sort({ createdAt: 1 })
      .limit(500)
      .toArray();
    res.json(messages.map((m) => ({
      id: m._id.toString(),
      orderId: m.orderId,
      senderId: m.senderId,
      senderName: m.senderName,
      senderRole: m.senderRole,
      text: m.text,
      createdAt: m.createdAt,
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/chats/:orderId', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { text } = req.body || {};
    if (!text?.trim()) return res.status(400).json({ error: 'text required' });
    const db = getDB();
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
    const msg = {
      orderId: req.params.orderId,
      senderId: req.user.id,
      senderName: user ? `${user.name || 'Team'}`.trim() : 'Team',
      senderRole: 'team',
      text: text.trim(),
      createdAt: new Date(),
    };
    const result = await db.collection('chat_messages').insertOne(msg);
    res.status(201).json({ id: result.insertedId.toString(), ...msg });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// SCHEDULED CALLS (all)
// ──────────────────────────────────────────────

router.get('/scheduled-calls', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.orderId) filter.orderId = String(req.query.orderId);
    const list = await db.collection('scheduled_calls').find(filter).sort({ date: -1, createdAt: -1 }).limit(100).toArray();
    res.json(list.map((s) => ({
      id: s._id.toString(),
      ...s,
      _id: undefined,
      contactHistory: s.contactHistory || [],
      verified: s.verified || false,
      verifiedAt: s.verifiedAt || null,
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/scheduled-calls/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { status, verified, contact } = req.body || {};
    const db = getDB();
    const id = req.params.id;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid id' });
    const updates = { updatedAt: new Date() };
    if (status !== undefined) updates.status = status || 'acknowledged';
    if (verified === true) {
      updates.verified = true;
      updates.verifiedAt = new Date();
    }
    if (contact && typeof contact === 'object') {
      const entry = {
        at: new Date(),
        contactMethod: contact.contactMethod === 'Email' ? 'Email' : 'Mobile',
        note: String(contact.note || ''),
        conversationScenario: String(contact.conversationScenario || ''),
        admin: String(contact.admin || (req.user && req.user.name) || 'Admin'),
      };
      const doc = await db.collection('scheduled_calls').findOneAndUpdate(
        { _id: new ObjectId(id) },
        { $push: { contactHistory: entry }, $set: updates },
        { returnDocument: 'after' },
      );
      if (doc && doc.verified && doc.orderId && ObjectId.isValid(doc.orderId)) {
        await db.collection('orders').updateOne(
          { _id: new ObjectId(doc.orderId) },
          { $set: { contactVerified: true, contactVerifiedAt: doc.verifiedAt || new Date(), updatedAt: new Date() } },
        ).catch(() => {});
      }
      return res.json({ success: true, contactHistory: (doc && doc.contactHistory) || [] });
    }
    const doc = await db.collection('scheduled_calls').findOne({ _id: new ObjectId(id) });
    if (updates.verified && doc && doc.orderId && ObjectId.isValid(doc.orderId)) {
      await db.collection('orders').updateOne(
        { _id: new ObjectId(doc.orderId) },
        { $set: { contactVerified: true, contactVerifiedAt: updates.verifiedAt || new Date(), updatedAt: new Date() } },
      ).catch(() => {});
    }
    await db.collection('scheduled_calls').updateOne(
      { _id: new ObjectId(id) },
      { $set: updates },
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/scheduled-calls', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { orderId, userId, contactMethod, note, conversationScenario, admin } = req.body || {};
    if (!orderId) return res.status(400).json({ error: 'orderId required' });
    const db = getDB();
    const existing = await db.collection('scheduled_calls').findOne({ orderId: String(orderId) });
    if (existing) {
      const entry = {
        at: new Date(),
        contactMethod: contactMethod === 'Email' ? 'Email' : 'Mobile',
        note: String(note || ''),
        conversationScenario: String(conversationScenario || ''),
        admin: String(admin || (req.user && req.user.name) || 'Admin'),
      };
      await db.collection('scheduled_calls').updateOne(
        { _id: existing._id },
        { $push: { contactHistory: entry }, $set: { updatedAt: new Date() } },
      );
      const updated = await db.collection('scheduled_calls').findOne({ _id: existing._id });
      return res.status(200).json({ id: updated._id.toString(), ...updated, _id: undefined, contactHistory: updated.contactHistory || [] });
    }
    const now = new Date();
    const firstEntry = {
      at: now,
      contactMethod: contactMethod === 'Email' ? 'Email' : 'Mobile',
      note: String(note || ''),
      conversationScenario: String(conversationScenario || ''),
      admin: String(admin || (req.user && req.user.name) || 'Admin'),
    };
    const doc = {
      orderId: String(orderId),
      userId: userId || null,
      date: now,
      scheduledAt: now,
      status: 'pending',
      contactHistory: [firstEntry],
      verified: false,
      verifiedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    const result = await db.collection('scheduled_calls').insertOne(doc);
    const inserted = await db.collection('scheduled_calls').findOne({ _id: result.insertedId });
    res.status(201).json({ id: inserted._id.toString(), ...inserted, _id: undefined });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// ACCOUNT DELETIONS
// ──────────────────────────────────────────────

router.get('/account-deletions', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    const list = await db.collection('account_deletions').find(filter).sort({ createdAt: -1, requestedAt: -1 }).limit(50).toArray();
    res.json(
      list.map((d) => {
        const rawUid = d.userId;
        const userIdNorm = rawUid != null ? String(rawUid) : undefined;
        return {
          id: d._id.toString(),
          userId: userIdNorm,
          userName: d.userName,
          userEmail: d.userEmail,
          userPhone: d.userPhone,
          status: d.status,
          reason: d.reason,
          type: d.type,
          requestedAt: d.requestedAt,
          createdAt: d.createdAt ?? d.requestedAt,
          updatedAt: d.updatedAt,
          deletedAt: d.deletedAt,
          deletedBy: d.deletedBy != null ? String(d.deletedBy) : undefined,
          deletedByName: d.deletedByName,
        };
      }),
    );
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/account-deletions/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { status } = req.body || {};
    if (!status) return res.status(400).json({ error: 'status required' });
    const db = getDB();
    await db.collection('account_deletions').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { status, updatedAt: new Date() } },
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// LOGIN HISTORY
// ──────────────────────────────────────────────

router.get('/login-history', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.userId) filter.userId = req.query.userId;
    const list = await db.collection('login_history').find(filter).sort({ loggedInAt: -1 }).limit(100).toArray();
    res.json(list.map((l) => ({ id: l._id.toString(), ...l, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// STATS / OVERVIEW
// ──────────────────────────────────────────────

router.get('/stats', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const [users, orders, transactions, callbacks, kyc, artisanal, alerts] = await Promise.all([
      db.collection('users').countDocuments({}),
      db.collection('orders').countDocuments({}),
      db.collection('transactions').countDocuments({}),
      db.collection('callbacks').countDocuments({ status: 'pending' }),
      db.collection('kyc_documents').countDocuments({}),
      db.collection('artisanal_profiles').countDocuments({}),
      db.collection('security_alerts').countDocuments({ dismissed: { $ne: true } }),
    ]);
    res.json({ users, orders, transactions, pendingCallbacks: callbacks, kycDocuments: kyc, artisanalProfiles: artisanal, activeAlerts: alerts });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ══════════════════════════════════════════════
// PHASE 3 — NEW MODULE ENDPOINTS
// ══════════════════════════════════════════════

// ──────────────────────────────────────────────
// DISPUTES
// ──────────────────────────────────────────────

router.get('/disputes', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    const list = await db.collection('disputes').find(filter).sort({ createdAt: -1 }).limit(200).toArray();
    res.json(list.map((d) => ({ id: d._id.toString(), ...d, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch disputes' });
  }
});

router.get('/disputes/metrics', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const col = db.collection('disputes');
    const [total, open, resolved, escalated] = await Promise.all([
      col.countDocuments({}),
      col.countDocuments({ status: 'open' }),
      col.countDocuments({ status: 'resolved' }),
      col.countDocuments({ escalated: true }),
    ]);
    const pipeline = [
      { $match: { status: 'resolved', resolvedAt: { $exists: true }, createdAt: { $exists: true } } },
      { $project: { days: { $divide: [{ $subtract: ['$resolvedAt', '$createdAt'] }, 86400000] } } },
      { $group: { _id: null, avg: { $avg: '$days' } } },
    ];
    const avgRes = await col.aggregate(pipeline).toArray();
    const valuePipeline = [
      { $match: { status: 'open' } },
      { $group: { _id: null, total: { $sum: '$value' } } },
    ];
    const valRes = await col.aggregate(valuePipeline).toArray();
    res.json({
      total, open, resolved, escalated,
      avgResolutionDays: avgRes[0]?.avg ? Math.round(avgRes[0].avg * 10) / 10 : 0,
      valueAtDispute: valRes[0]?.total || 0,
      resolutionRate: total > 0 ? Math.round((resolved / total) * 100) : 0,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/disputes/escalations', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('disputes').find({ escalated: true }).sort({ escalatedAt: -1 }).limit(50).toArray();
    res.json(list.map((d) => ({ id: d._id.toString(), ...d, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/disputes/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const d = await db.collection('disputes').findOne({ _id: new ObjectId(req.params.id) });
    if (!d) return res.status(404).json({ error: 'Not found' });
    res.json({ id: d._id.toString(), ...d, _id: undefined });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/disputes', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { orderId, buyerId, sellerId, reason, value, category } = req.body || {};
    if (!orderId || !reason) return res.status(400).json({ error: 'orderId and reason required' });
    const db = getDB();
    const doc = {
      orderId, buyerId, sellerId, reason, value: value || 0, category: category || 'general',
      status: 'open', escalated: false, timeline: [{ action: 'opened', at: new Date(), actor: req.user.name || 'Admin' }],
      createdAt: new Date(), updatedAt: new Date(),
    };
    const result = await db.collection('disputes').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/disputes/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { status, resolution, escalated, notes } = req.body || {};
    const db = getDB();
    const updates = { updatedAt: new Date() };
    if (status) updates.status = status;
    if (resolution) updates.resolution = resolution;
    if (typeof escalated === 'boolean') {
      updates.escalated = escalated;
      if (escalated) updates.escalatedAt = new Date();
    }
    if (status === 'resolved') updates.resolvedAt = new Date();
    const push = {};
    if (notes || status) {
      push.$push = { timeline: { action: status || 'note', at: new Date(), actor: req.user.name || 'Admin', notes: notes || '' } };
    }
    await db.collection('disputes').updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: updates, ...push },
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// NOTIFICATIONS
// ──────────────────────────────────────────────

router.get('/notifications', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.read === 'false') filter.read = { $ne: true };
    const list = await db.collection('notifications').find(filter).sort({ createdAt: -1 }).limit(100).toArray();
    res.json(list.map((n) => ({ id: n._id.toString(), ...n, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/notifications', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { title, message, type, targetUserId } = req.body || {};
    if (!title) return res.status(400).json({ error: 'title required' });
    const db = getDB();
    const doc = { title, message: message || '', type: type || 'info', targetUserId, read: false, createdAt: new Date() };
    const result = await db.collection('notifications').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/notifications/:id/read', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    await db.collection('notifications').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { read: true, readAt: new Date() } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.delete('/notifications/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    await db.collection('notifications').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// AUDIT LOG
// ──────────────────────────────────────────────

router.get('/audit-log', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.type) filter.type = req.query.type;
    if (req.query.actor) filter.actor = { $regex: req.query.actor, $options: 'i' };
    if (req.query.search) {
      filter.$or = [
        { action: { $regex: req.query.search, $options: 'i' } },
        { details: { $regex: req.query.search, $options: 'i' } },
        { actor: { $regex: req.query.search, $options: 'i' } },
      ];
    }
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 50);
    const skip = (page - 1) * limit;
    const [list, total] = await Promise.all([
      db.collection('audit_log').find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
      db.collection('audit_log').countDocuments(filter),
    ]);
    res.json({ entries: list.map((a) => ({ id: a._id.toString(), ...a, _id: undefined })), total, page, limit });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/audit-log', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { action, type, details, targetId, targetType } = req.body || {};
    if (!action) return res.status(400).json({ error: 'action required' });
    const db = getDB();
    const doc = { action, type: type || 'admin', details: details || '', actor: req.user.name || 'Admin', actorId: req.user.id, targetId, targetType, createdAt: new Date() };
    const result = await db.collection('audit_log').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// ANALYTICS
// ──────────────────────────────────────────────

router.get('/analytics/overview', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const [users, orders, txCount, disputes] = await Promise.all([
      db.collection('users').countDocuments({}),
      db.collection('orders').countDocuments({}),
      db.collection('transactions').countDocuments({}),
      db.collection('disputes').countDocuments({ status: 'open' }),
    ]);
    const volumePipeline = [{ $group: { _id: null, total: { $sum: { $ifNull: ['$total', 0] } } } }];
    const volRes = await db.collection('transactions').aggregate(volumePipeline).toArray();
    res.json({ totalUsers: users, totalOrders: orders, totalTransactions: txCount, openDisputes: disputes, tradingVolume: volRes[0]?.total || 0 });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/analytics/trading-volume', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const days = parseInt(req.query.days) || 30;
    const since = new Date(Date.now() - days * 86400000);
    const pipeline = [
      { $match: { createdAt: { $gte: since } } },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, volume: { $sum: { $ifNull: ['$total', 0] } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ];
    const data = await db.collection('transactions').aggregate(pipeline).toArray();
    res.json(data.map((d) => ({ date: d._id, volume: d.volume, count: d.count })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/analytics/mineral-categories', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const pipeline = [
      { $group: { _id: { $ifNull: ['$mineralName', '$mineral', 'Unknown'] }, count: { $sum: 1 }, totalValue: { $sum: { $ifNull: ['$totalDue', '$subtotal', 0] } } } },
      { $sort: { totalValue: -1 } },
      { $limit: 20 },
    ];
    const data = await db.collection('orders').aggregate(pipeline).toArray();
    res.json(data.map((d) => ({ mineral: d._id || 'Unknown', count: d.count, totalValue: d.totalValue })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/analytics/top-users', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const limit = Math.min(50, parseInt(req.query.limit) || 10);
    const pipeline = [
      { $group: { _id: '$userId', totalVolume: { $sum: { $ifNull: ['$total', 0] } }, txCount: { $sum: 1 } } },
      { $sort: { totalVolume: -1 } },
      { $limit: limit },
    ];
    const data = await db.collection('transactions').aggregate(pipeline).toArray();
    const userIds = data.map((d) => d._id).filter(Boolean);
    const users = userIds.length > 0
      ? await db.collection('users').find({ _id: { $in: userIds.map((id) => { try { return new ObjectId(id); } catch { return id; } }) } }).toArray()
      : [];
    const userMap = {};
    users.forEach((u) => { userMap[u._id.toString()] = u; });
    res.json(data.map((d) => {
      const u = userMap[d._id] || {};
      return { userId: d._id, name: u.name || 'Unknown', email: u.email || '', totalVolume: d.totalVolume, txCount: d.txCount };
    }));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/analytics/regional', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const pipeline = [
      { $group: { _id: '$countryCode', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 20 },
    ];
    const data = await db.collection('users').aggregate(pipeline).toArray();
    res.json(data.map((d) => ({ region: d._id || 'Unknown', userCount: d.count })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// CONTENT / CMS
// ──────────────────────────────────────────────

router.get('/content/banners', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('banners').find({}).sort({ position: 1, createdAt: -1 }).toArray();
    const out = await Promise.all(list.map(async (b) => {
      const item = { id: b._id.toString(), ...b, _id: undefined };
      if (b.imageKey) {
        try {
          item.imageUrl = await presignedUrl(b.imageKey, { scope: 'admin', expiresIn: 86400 });
        } catch (e) {
          console.warn('Banner presign error:', e.message);
        }
      }
      return item;
    }));
    res.json(out);
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

function normalizeBannerPlacement(input = {}) {
  const fitRaw = String(input.fitMode || '').trim().toLowerCase();
  const fitMode = fitRaw === 'contain' ? 'contain' : 'cover';
  const n = (v, fallback = 0) => {
    const num = Number(v);
    return Number.isFinite(num) ? num : fallback;
  };
  // Range is percent offset around center so UI is predictable.
  const offsetX = Math.max(-100, Math.min(100, n(input.offsetX, 0)));
  const offsetY = Math.max(-100, Math.min(100, n(input.offsetY, 0)));
  // Zoom is a multiplier; minimum 0.5 to allow zoom-out, cap to avoid extreme values.
  const zoom = Math.max(0.5, Math.min(3, n(input.zoom, 1)));
  return { fitMode, offsetX, offsetY, zoom };
}

// Proxy remote banner image for dashboard cropper to avoid browser CORS issues.
router.get('/content/banners/proxy-image', async (req, res) => {
  try {
    const raw = String(req.query.url || '').trim();
    if (!raw) return res.status(400).json({ error: 'url is required' });
    let u;
    try {
      u = new URL(raw);
    } catch {
      return res.status(400).json({ error: 'invalid url' });
    }
    if (!['http:', 'https:'].includes(u.protocol)) {
      return res.status(400).json({ error: 'unsupported protocol' });
    }

    const r = await fetch(u.toString(), {
      method: 'GET',
      redirect: 'follow',
      // Avoid passing dashboard referrer details to external hosts.
      referrerPolicy: 'no-referrer',
    });
    if (!r.ok) return res.status(502).json({ error: `upstream ${r.status}` });
    const contentType = String(r.headers.get('content-type') || '').toLowerCase();
    if (!contentType.startsWith('image/')) {
      return res.status(415).json({ error: 'upstream is not an image' });
    }
    const ab = await r.arrayBuffer();
    const buf = Buffer.from(ab);
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    return res.status(200).send(buf);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to proxy image' });
  }
});

router.post('/content/banners', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { title, imageUrl, imageKey, targetPage, linkUrl, position, active, sponsoredTag, description } = req.body || {};
    const placement = normalizeBannerPlacement(req.body || {});
    // Allow partial saves: admin can save with only the fields they filled (no required fields)
    const db = getDB();
    const doc = {
      title: title != null ? String(title) : '',
      imageUrl: imageUrl != null ? String(imageUrl) : '',
      imageKey: imageKey != null && String(imageKey).trim() ? String(imageKey).trim() : '',
      targetPage: targetPage != null ? String(targetPage) : 'homepage',
      linkUrl: linkUrl != null ? String(linkUrl) : '',
      position: position != null ? Number(position) : 0,
      active: active !== false,
      clicks: 0,
      sponsoredTag: sponsoredTag != null ? String(sponsoredTag) : '',
      description: description != null ? String(description) : '',
      fitMode: placement.fitMode,
      offsetX: placement.offsetX,
      offsetY: placement.offsetY,
      zoom: placement.zoom,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const result = await db.collection('banners').insertOne(doc);
    await bumpBannerCacheVersion(db);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/content/banners/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const allowed = ['title', 'imageUrl', 'imageKey', 'targetPage', 'linkUrl', 'position', 'active', 'sponsoredTag', 'description'];
    const updates = { updatedAt: new Date() };
    allowed.forEach((k) => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    if (
      req.body.fitMode !== undefined
      || req.body.offsetX !== undefined
      || req.body.offsetY !== undefined
      || req.body.zoom !== undefined
    ) {
      const placement = normalizeBannerPlacement(req.body || {});
      updates.fitMode = placement.fitMode;
      updates.offsetX = placement.offsetX;
      updates.offsetY = placement.offsetY;
      updates.zoom = placement.zoom;
    }
    if (req.body.imageKey === '') updates.imageKey = '';
    await db.collection('banners').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    await bumpBannerCacheVersion(db);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.delete('/content/banners/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    await db.collection('banners').deleteOne({ _id: new ObjectId(req.params.id) });
    await bumpBannerCacheVersion(db);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

const LEGAL_CONTENT_KEY = 'legal';
router.get('/content/legal', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const doc = await db.collection('content').findOne({ key: LEGAL_CONTENT_KEY });
    const value = (doc && doc.value) || {};
    res.json({
      termsOfService: value.termsOfService != null ? String(value.termsOfService) : '',
      privacyPolicy: value.privacyPolicy != null ? String(value.privacyPolicy) : '',
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/content/legal', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { termsOfService, privacyPolicy } = req.body || {};
    const db = getDB();
    const doc = await db.collection('content').findOne({ key: LEGAL_CONTENT_KEY });
    const current = (doc && doc.value) || { termsOfService: '', privacyPolicy: '' };
    const next = {
      termsOfService: termsOfService !== undefined ? String(termsOfService) : current.termsOfService,
      privacyPolicy: privacyPolicy !== undefined ? String(privacyPolicy) : current.privacyPolicy,
    };
    await db.collection('content').updateOne(
      { key: LEGAL_CONTENT_KEY },
      { $set: { key: LEGAL_CONTENT_KEY, value: next, updatedAt: new Date() } },
      { upsert: true }
    );
    res.json({ termsOfService: next.termsOfService, privacyPolicy: next.privacyPolicy });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/content/videos', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('training_videos').find({}).sort({ createdAt: -1 }).toArray();
    res.json(list.map((v) => ({ id: v._id.toString(), ...v, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/content/videos', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { title, url, description, category, duration, xpReward, chapters } = req.body || {};
    if (!title || !url) return res.status(400).json({ error: 'title and url required' });
    const db = getDB();
    const doc = {
      title,
      url,
      description: description || '',
      category: category || 'general',
      duration: duration || '',
      xpReward: xpReward || '',
      chapters: Array.isArray(chapters) ? chapters : [],
      views: 0,
      createdAt: new Date(),
    };
    const result = await db.collection('training_videos').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/content/videos/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const allowed = ['title', 'url', 'description', 'category', 'duration', 'xpReward', 'chapters'];
    const updates = { updatedAt: new Date() };
    allowed.forEach((k) => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    if (req.body.chapters && Array.isArray(req.body.chapters)) updates.chapters = req.body.chapters;
    await db.collection('training_videos').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.delete('/content/videos/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    await db.collection('training_videos').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// Market insights (dashboard CRUD; app reads via GET /api/market-insights)
router.get('/content/market-insights', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('market_insights').find({}).sort({ order: 1, createdAt: -1 }).limit(20).toArray();
    res.json(list.map((m) => ({ id: m._id?.toString(), label: m.label, content: m.content || '', trend: m.trend, type: m.type, enabled: m.enabled !== false })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/content/market-insights', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { label, content, trend, type } = req.body || {};
    if (!label) return res.status(400).json({ error: 'label required' });
    const db = getDB();
    const doc = { label: String(label), content: content != null ? String(content) : '', trend: trend || 'neutral', type: type || 'price', enabled: true, createdAt: new Date() };
    const result = await db.collection('market_insights').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/content/market-insights/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const updates = { updatedAt: new Date() };
    if (req.body.enabled !== undefined) updates.enabled = req.body.enabled;
    if (req.body.label !== undefined) updates.label = req.body.label;
    if (req.body.content !== undefined) updates.content = req.body.content;
    if (req.body.trend !== undefined) updates.trend = req.body.trend;
    await db.collection('market_insights').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.delete('/content/market-insights/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    await db.collection('market_insights').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// Recent activity (dashboard CRUD; app reads via GET /api/content/recent-activity)
router.get('/content/recent-activity', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('recent_activity').find({}).sort({ createdAt: -1 }).limit(50).toArray();
    res.json(list.map((a) => ({ id: a._id?.toString(), title: a.title, body: a.body || '', type: a.type || 'info', createdAt: a.createdAt })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/content/recent-activity', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { title, body, type } = req.body || {};
    if (!title) return res.status(400).json({ error: 'title required' });
    const db = getDB();
    const doc = { title: String(title), body: body || '', type: type || 'info', createdAt: new Date() };
    const result = await db.collection('recent_activity').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.delete('/content/recent-activity/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    await db.collection('recent_activity').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// Broadcast notification (creates in-app notifications for target user groups)
router.post('/notifications/broadcast', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { title, body, targetAudience } = req.body || {};
    if (!title) return res.status(400).json({ error: 'title required' });
    const db = getDB();
    const audience = targetAudience || { buyers: true, sellers: true };
    let userIds = [];
    if (audience.buyers || audience.sellers) {
      const users = await db.collection('users').find({}).project({ _id: 1 }).toArray();
      userIds = users.map((u) => u._id.toString());
    }
    const inserted = [];
    for (const uid of userIds) {
      const doc = { userId: uid, title: String(title), body: body || '', createdAt: new Date() };
      const r = await db.collection('notifications').insertOne(doc);
      inserted.push({ id: r.insertedId.toString(), userId: uid });
    }
    res.status(201).json({ success: true, count: inserted.length });
  } catch (err) {
    console.error('POST /dashboard/notifications/broadcast error:', err);
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// LOGISTICS
// ──────────────────────────────────────────────

router.get('/logistics/shipments', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.orderId) filter.orderId = String(req.query.orderId);
    const list = await db.collection('shipments').find(filter).sort({ createdAt: -1 }).limit(200).toArray();
    res.json(list.map((s) => ({ id: s._id.toString(), ...s, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/logistics/shipments/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const s = await db.collection('shipments').findOne({ _id: new ObjectId(req.params.id) });
    if (!s) return res.status(404).json({ error: 'Not found' });
    res.json({ id: s._id.toString(), ...s, _id: undefined });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/logistics/shipments', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { orderId, origin, destination, carrier, mineral, weight, value, estimatedDelivery, trackingNumber, trackingUrl, carrierName, contactPhone, contactEmail, notes, shippingAmount, shippingCurrency } = req.body || {};
    if (!orderId) return res.status(400).json({ error: 'orderId required' });
    const db = getDB();
    const doc = {
      orderId,
      origin: origin || '', destination: destination || '', carrier: carrier || carrierName || '', mineral: mineral || '', weight: weight || '', value: value || 0,
      status: 'pending', progress: 0, estimatedDelivery: estimatedDelivery || null,
      trackingNumber: trackingNumber || '', trackingUrl: trackingUrl || '', carrierName: carrierName || '',
      contactPhone: contactPhone || '', contactEmail: contactEmail || '', notes: notes || '',
      shippingAmount: shippingAmount || '', shippingCurrency: shippingCurrency || 'USD',
      timeline: [{ status: 'created', at: new Date(), note: 'Shipment created' }],
      createdAt: new Date(), updatedAt: new Date(),
    };
    const result = await db.collection('shipments').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/logistics/shipments/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const allowed = ['status', 'progress', 'trackingNumber', 'trackingUrl', 'carrier', 'carrierName', 'estimatedDelivery', 'actualDelivery', 'notes', 'contactPhone', 'contactEmail', 'shippingAmount', 'shippingCurrency'];
    const updates = { updatedAt: new Date() };
    allowed.forEach((k) => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    const push = {};
    if (req.body.status) {
      push.$push = { timeline: { status: req.body.status, at: new Date(), note: req.body.notes || '' } };
    }
    await db.collection('shipments').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates, ...push });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/logistics/metrics', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const col = db.collection('shipments');
    const [total, inTransit, delivered, damaged] = await Promise.all([
      col.countDocuments({}),
      col.countDocuments({ status: 'in-transit' }),
      col.countDocuments({ status: 'delivered' }),
      col.countDocuments({ status: 'damaged' }),
    ]);
    const valuePipeline = [
      { $match: { status: 'in-transit' } },
      { $group: { _id: null, total: { $sum: '$value' } } },
    ];
    const valRes = await col.aggregate(valuePipeline).toArray();
    res.json({
      total, inTransit, delivered, damaged,
      inTransitValue: valRes[0]?.total || 0,
      onTimeRate: total > 0 ? Math.round((delivered / Math.max(1, delivered + damaged)) * 100) : 0,
      damageRate: total > 0 ? Math.round((damaged / total) * 1000) / 10 : 0,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// INSURANCE
// ──────────────────────────────────────────────

router.get('/insurance/policies', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    const list = await db.collection('insurance_policies').find(filter).sort({ createdAt: -1 }).limit(200).toArray();
    res.json(list.map((p) => ({ id: p._id.toString(), ...p, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/insurance/policies', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { orderId, userId, provider, coverageType, insuredValue, premium, expiresAt } = req.body || {};
    if (!orderId) return res.status(400).json({ error: 'orderId required' });
    const db = getDB();
    const doc = {
      orderId, userId, provider: provider || '', coverageType: coverageType || 'transit',
      insuredValue: insuredValue || 0, premium: premium || 0, status: 'active',
      expiresAt: expiresAt ? new Date(expiresAt) : null, createdAt: new Date(), updatedAt: new Date(),
    };
    const result = await db.collection('insurance_policies').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/insurance/claims', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    const list = await db.collection('insurance_claims').find(filter).sort({ createdAt: -1 }).limit(200).toArray();
    res.json(list.map((c) => ({ id: c._id.toString(), ...c, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/insurance/claims', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { policyId, orderId, reason, claimAmount, evidence } = req.body || {};
    if (!policyId || !reason) return res.status(400).json({ error: 'policyId and reason required' });
    const db = getDB();
    const doc = {
      policyId, orderId, reason, claimAmount: claimAmount || 0, evidence: evidence || [],
      status: 'pending', timeline: [{ action: 'filed', at: new Date(), actor: req.user.name || 'Admin' }],
      createdAt: new Date(), updatedAt: new Date(),
    };
    const result = await db.collection('insurance_claims').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/insurance/claims/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { status, notes, payoutAmount } = req.body || {};
    const db = getDB();
    const updates = { updatedAt: new Date() };
    if (status) updates.status = status;
    if (payoutAmount !== undefined) updates.payoutAmount = payoutAmount;
    if (status === 'approved') updates.approvedAt = new Date();
    const push = {};
    if (status || notes) {
      push.$push = { timeline: { action: status || 'note', at: new Date(), actor: req.user.name || 'Admin', notes: notes || '' } };
    }
    await db.collection('insurance_claims').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates, ...push });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/insurance/providers', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('insurance_providers').find({}).sort({ name: 1 }).toArray();
    res.json(list.map((p) => ({ id: p._id.toString(), ...p, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/insurance/providers', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { name, type, contactEmail, regions, coverageTypes } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name required' });
    const db = getDB();
    const doc = { name, type: type || 'underwriter', contactEmail: contactEmail || '', regions: regions || [], coverageTypes: coverageTypes || [], active: true, createdAt: new Date() };
    const result = await db.collection('insurance_providers').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/insurance/metrics', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const [policies, activePolicies, claims, pendingClaims] = await Promise.all([
      db.collection('insurance_policies').countDocuments({}),
      db.collection('insurance_policies').countDocuments({ status: 'active' }),
      db.collection('insurance_claims').countDocuments({}),
      db.collection('insurance_claims').countDocuments({ status: 'pending' }),
    ]);
    const valuePipeline = [
      { $match: { status: 'active' } },
      { $group: { _id: null, insured: { $sum: '$insuredValue' }, premiums: { $sum: '$premium' } } },
    ];
    const valRes = await db.collection('insurance_policies').aggregate(valuePipeline).toArray();
    const claimsPipeline = [{ $group: { _id: null, total: { $sum: '$claimAmount' } } }];
    const claimVal = await db.collection('insurance_claims').aggregate(claimsPipeline).toArray();
    res.json({
      totalPolicies: policies, activePolicies, totalClaims: claims, pendingClaims,
      totalInsuredValue: valRes[0]?.insured || 0, totalPremiums: valRes[0]?.premiums || 0,
      totalClaimValue: claimVal[0]?.total || 0,
      lossRatio: (valRes[0]?.premiums || 0) > 0 ? Math.round(((claimVal[0]?.total || 0) / valRes[0].premiums) * 1000) / 10 : 0,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// PARTNERS / TESTING
// ──────────────────────────────────────────────

router.get('/partners/testing-labs', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('testing_labs').find({}).sort({ name: 1 }).toArray();
    res.json(list.map((l) => ({ id: l._id.toString(), ...l, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/partners/testing-labs', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { name, location, certifications, turnaroundDays, contactEmail, minerals } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name required' });
    const db = getDB();
    const doc = { name, location: location || '', certifications: certifications || [], turnaroundDays: turnaroundDays || 0, contactEmail: contactEmail || '', minerals: minerals || [], active: true, createdAt: new Date() };
    const result = await db.collection('testing_labs').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

/** Custom test types for 3rd Party Testing Details (admin-created). */
router.get('/partners/testing-test-types', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('testing_test_types').find({}).sort({ name: 1 }).toArray();
    res.json(list.map((d) => d.name).filter(Boolean));
  } catch (err) {
    res.json([]);
  }
});

router.post('/partners/testing-test-types', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const name = (req.body && req.body.name) ? String(req.body.name).trim() : '';
    if (!name) return res.status(400).json({ error: 'name required' });
    const db = getDB();
    const existing = await db.collection('testing_test_types').findOne({ name: { $regex: new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') } });
    if (existing) return res.status(409).json({ error: 'Already exists' });
    await db.collection('testing_test_types').insertOne({ name, createdAt: new Date() });
    res.status(201).json({ success: true, name });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/partners/active-tests', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    const list = await db.collection('testing_orders').find(filter).project({ reportFileBuffer: 0 }).sort({ createdAt: -1 }).limit(200).toArray();
    res.json(list.map((t) => ({ id: t._id.toString(), ...t, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/partners/active-tests', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const body = req.body || {};
    const db = getDB();
    const isThirdParty =
      body.thirdPartySellerTesting === true ||
      body.workflow === 'third_party_seller_testing' ||
      (body.company && body.agent && body.testType && body.visitDate);

    if (isThirdParty) {
      const {
        orderId,
        company,
        customLabName,
        agent,
        teamMember,
        testType,
        visitDate,
        testCost,
        invoice,
        payStatus,
        amtPaid,
        payDate,
        internalNotes,
        reportFileName,
        userId,
        mineral,
      } = body;
      if (!orderId || !company || !agent || !testType || !visitDate) {
        return res.status(400).json({ error: 'orderId, company, agent, testType, visitDate required' });
      }
      if (company === 'Other' && !(customLabName && String(customLabName).trim())) {
        return res.status(400).json({ error: 'customLabName required when company is Other' });
      }
      const dup = await db.collection('testing_orders').findOne({
        orderId: String(orderId),
        workflow: 'third_party_seller_testing',
      });
      if (dup) {
        return res.status(409).json({
          error: 'Testing record already exists for this order',
          id: dup._id.toString(),
        });
      }
      const labDisplay = company === 'Other' ? String(customLabName).trim() : String(company);
      const now = new Date();
      const doc = {
        workflow: 'third_party_seller_testing',
        orderId: String(orderId),
        userId: userId ? String(userId) : '',
        labName: labDisplay,
        company: String(company),
        customLabName: customLabName ? String(customLabName) : '',
        agent: String(agent),
        teamMember: teamMember ? String(teamMember) : '',
        testType: String(testType),
        visitDate: String(visitDate),
        testCost: testCost !== undefined && testCost !== '' ? Number(testCost) : null,
        invoice: invoice ? String(invoice) : '',
        payStatus: payStatus ? String(payStatus) : 'Pending',
        amtPaid: amtPaid !== undefined && amtPaid !== '' ? Number(amtPaid) : null,
        payDate: payDate ? String(payDate) : '',
        internalNotes: internalNotes ? String(internalNotes) : '',
        reportFileName: reportFileName ? String(reportFileName) : '',
        isVerified: false,
        customerCompany: labDisplay,
        customerAgent: String(agent),
        customerVisitDate: String(visitDate),
        customerTestType: String(testType),
        customerLocation: '',
        customerMessage: '',
        sentVia: [],
        sentAt: null,
        internalSavedAt: now.toISOString(),
        mineral: mineral ? String(mineral) : '',
        status: 'in-progress',
        progress: 0,
        results: null,
        submittedAt: now,
        createdAt: now,
        updatedAt: now,
      };
      const result = await db.collection('testing_orders').insertOne(doc);
      return res.status(201).json({ id: result.insertedId.toString(), ...doc });
    }

    const { orderId, labId, labName, mineral, testType, sampleWeight } = body;
    if (!orderId || !labName) return res.status(400).json({ error: 'orderId and labName required' });
    const doc = {
      orderId,
      labId,
      labName,
      mineral: mineral || '',
      testType: testType || 'purity',
      sampleWeight: sampleWeight || '',
      status: 'in-progress',
      progress: 0,
      results: null,
      submittedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const result = await db.collection('testing_orders').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

const THIRD_PARTY_PATCH_KEYS = new Set([
  'status',
  'progress',
  'results',
  'notes',
  'company',
  'customLabName',
  'agent',
  'teamMember',
  'testType',
  'visitDate',
  'testCost',
  'invoice',
  'payStatus',
  'amtPaid',
  'payDate',
  'internalNotes',
  'reportFileName',
  'labName',
  'customerCompany',
  'customerAgent',
  'customerVisitDate',
  'customerTestType',
  'customerLocation',
  'customerMessage',
  'isVerified',
  'verifiedAt',
  'verifiedBy',
  'sentVia',
  'sentAt',
  'internalSavedAt',
  'mineral',
  'isConfirmed',
  'confirmedAt',
  'testResultStatus',
  'testResultRef',
  'testResultGrade',
  'testResultWeight',
  'testResultNotes',
  'resultSentVia',
]);

router.patch('/partners/active-tests/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const body = req.body || {};
    const updates = { updatedAt: new Date() };
    for (const k of Object.keys(body)) {
      if (THIRD_PARTY_PATCH_KEYS.has(k)) updates[k] = body[k];
    }
    if (body.status === 'completed') updates.completedAt = new Date();
    if (Object.keys(updates).length <= 1) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    await db.collection('testing_orders').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post(
  '/partners/active-tests/:id/report',
  authMiddleware,
  requireDashboard,
  reportUpload.single('file'),
  async (req, res) => {
    try {
      if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
      if (!req.file) return res.status(400).json({ error: 'file required (pdf, png, jpg)' });
      const db = getDB();
      await db.collection('testing_orders').updateOne(
        { _id: new ObjectId(req.params.id) },
        {
          $set: {
            reportFileName: req.file.originalname,
            reportFileBuffer: req.file.buffer,
            reportMimeType: req.file.mimetype,
            updatedAt: new Date(),
          },
        },
      );
      res.json({ success: true, reportFileName: req.file.originalname });
    } catch (err) {
      res.status(500).json({ error: 'Failed' });
    }
  },
);

router.get('/partners/metrics', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const [labs, activeTests, completed, pending] = await Promise.all([
      db.collection('testing_labs').countDocuments({}),
      db.collection('testing_orders').countDocuments({ status: 'in-progress' }),
      db.collection('testing_orders').countDocuments({ status: 'completed' }),
      db.collection('testing_orders').countDocuments({ status: 'pending' }),
    ]);
    res.json({ totalLabs: labs, activeTests, completedTests: completed, pendingTests: pending });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// Certification reports (lab certificates) – real-time from DB
router.get('/partners/certification-reports', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('certification_reports').find({}).sort({ issueDate: -1 }).limit(200).toArray();
    res.json(list.map((r) => ({
      id: r.certificateId || r._id?.toString(),
      issueDate: r.issueDate ? new Date(r.issueDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—',
      expiryDate: r.expiryDate ? new Date(r.expiryDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—',
      mineral: r.mineral || '—',
      status: r.status === 'expired' ? 'Expiring Soon' : 'Active',
    })));
  } catch (err) {
    res.json([]);
  }
});

// ──────────────────────────────────────────────
// ADMIN SETTINGS
// ──────────────────────────────────────────────

router.get('/admin/roles', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('admin_roles').find({}).sort({ name: 1 }).toArray();
    res.json(list.map((r) => ({ id: r._id.toString(), ...r, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/admin/roles', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { name, permissions, description } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name required' });
    const db = getDB();
    const doc = { name, permissions: permissions || {}, description: description || '', createdAt: new Date() };
    const result = await db.collection('admin_roles').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/admin/roles/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { permissions, description } = req.body || {};
    const db = getDB();
    const updates = { updatedAt: new Date() };
    if (permissions) updates.permissions = permissions;
    if (description !== undefined) updates.description = description;
    await db.collection('admin_roles').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.get('/admin/integrations', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('admin_integrations').find({}).sort({ name: 1 }).toArray();
    res.json(list.map((i) => ({ id: i._id.toString(), ...i, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.post('/admin/integrations', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { name, type, apiKey, webhookUrl, enabled } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name required' });
    const db = getDB();
    const doc = { name, type: type || 'webhook', apiKey: apiKey || '', webhookUrl: webhookUrl || '', enabled: enabled !== false, createdAt: new Date() };
    const result = await db.collection('admin_integrations').insertOne(doc);
    res.status(201).json({ id: result.insertedId.toString(), ...doc });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/admin/integrations/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const allowed = ['apiKey', 'webhookUrl', 'enabled', 'config'];
    const db = getDB();
    const updates = { updatedAt: new Date() };
    allowed.forEach((k) => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    await db.collection('admin_integrations').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

const DASHBOARD_ADMIN_ROLES = new Set(['ceo', 'operations_manager', 'support_agent', 'data_clerk']);

/**
 * Create a new dashboard admin (MongoDB). Only CEO can create accounts so new team members can sign in.
 * Body: { name, email, password, role }
 */
router.post('/admin/admins', authMiddleware, requireDashboard, async (req, res) => {
  try {
    if (!req.isAdmin) return res.status(403).json({ error: 'Admin token required' });
    if (req.user.role !== 'ceo') {
      return res.status(403).json({ error: 'Only a CEO can create new admin accounts' });
    }
    const { name, email, password, role } = req.body || {};
    const n = name != null ? String(name).trim() : '';
    const em = email != null ? String(email).trim().toLowerCase() : '';
    const pw = password != null ? String(password) : '';
    const r = role != null ? String(role).trim() : '';
    if (!n || !em || !pw) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }
    if (pw.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    if (!DASHBOARD_ADMIN_ROLES.has(r)) {
      return res.status(400).json({ error: 'Invalid role' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    const db = getDB();
    const taken = await db.collection('admin_users').findOne({ email: em });
    if (taken) {
      return res.status(409).json({ error: 'An admin with this email already exists' });
    }
    const passwordHash = await bcrypt.hash(pw, 10);
    const now = new Date();
    const doc = {
      name: n,
      email: em,
      passwordHash,
      role: r,
      status: 'Active',
      createdAt: now,
      updatedAt: now,
    };
    const result = await db.collection('admin_users').insertOne(doc);
    res.status(201).json({
      id: result.insertedId.toString(),
      name: doc.name,
      email: doc.email,
      role: doc.role,
      status: doc.status,
    });
  } catch (err) {
    console.error('Dashboard POST /admin/admins error:', err);
    res.status(500).json({ error: 'Failed to create admin' });
  }
});

router.get('/admin/admins', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('admin_users').find({}).project({ password: 0, passwordHash: 0 }).sort({ createdAt: -1 }).toArray();
    res.json(list.map((a) => ({ id: a._id.toString(), ...a, _id: undefined })));
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

router.patch('/admin/admins/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { role, status, name } = req.body || {};
    const db = getDB();
    const updates = { updatedAt: new Date() };
    if (role) updates.role = role;
    if (status) updates.status = status;
    if (name) updates.name = name;
    await db.collection('admin_users').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ──────────────────────────────────────────────
// PLATFORM SETTINGS (general config, security policies, notification defaults)
// ──────────────────────────────────────────────

const PLATFORM_DEFAULTS = {
  platformName: 'Mineral Bridge',
  supportEmail: 'support@mineralbridge.com',
  defaultCurrency: 'usd',
  timezone: 'utc',
  enforce2FA: true,
  sessionTimeoutMins: 30,
  strictKYCMode: false,
  emailAlerts: true,
  newOrders: true,
  newUsers: false,
  systemUpdates: true,
  marketing: false,
};

router.get('/platform-settings', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const doc = await db.collection('platform_settings').findOne({});
    const merged = { ...PLATFORM_DEFAULTS, ...(doc || {}), id: doc?._id?.toString() };
    delete merged._id;
    res.json(merged);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load platform settings' });
  }
});

router.patch('/platform-settings', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const allowed = ['platformName', 'supportEmail', 'defaultCurrency', 'timezone', 'enforce2FA', 'sessionTimeoutMins', 'strictKYCMode', 'emailAlerts', 'newOrders', 'newUsers', 'systemUpdates', 'marketing'];
    const db = getDB();
    const updates = { updatedAt: new Date() };
    allowed.forEach((k) => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
    if (Object.keys(updates).length <= 1) return res.json({ success: true });
    await db.collection('platform_settings').updateOne(
      {},
      { $set: updates },
      { upsert: true }
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update platform settings' });
  }
});

// ──────────────────────────────────────────────
// SEED SAMPLE DATA (Phase 3)
// ──────────────────────────────────────────────

router.post('/seed-phase3', async (req, res) => {
  try {
    const key = req.headers['x-dashboard-key'];
    if (key !== process.env.DASHBOARD_SECRET) return res.status(403).json({ error: 'Dashboard key required' });
    const db = getDB();
    const results = {};

    // Disputes
    const disputeCount = await db.collection('disputes').countDocuments({});
    if (disputeCount === 0) {
      await db.collection('disputes').insertMany([
        { orderId: 'ORD-001', buyerId: 'buyer1', sellerId: 'seller1', reason: 'Quality mismatch - purity below specification', value: 45000, category: 'quality', status: 'open', escalated: false, timeline: [{ action: 'opened', at: new Date(), actor: 'System' }], createdAt: new Date(), updatedAt: new Date() },
        { orderId: 'ORD-002', buyerId: 'buyer2', sellerId: 'seller2', reason: 'Late delivery - exceeded 30 day window', value: 12000, category: 'delivery', status: 'open', escalated: true, escalatedAt: new Date(), timeline: [{ action: 'opened', at: new Date(Date.now() - 86400000 * 3), actor: 'System' }, { action: 'escalated', at: new Date(), actor: 'Admin' }], createdAt: new Date(Date.now() - 86400000 * 3), updatedAt: new Date() },
        { orderId: 'ORD-003', buyerId: 'buyer3', sellerId: 'seller1', reason: 'Payment not received by seller', value: 8500, category: 'payment', status: 'resolved', resolution: 'Payment confirmed after bank verification', resolvedAt: new Date(Date.now() - 86400000), escalated: false, timeline: [{ action: 'opened', at: new Date(Date.now() - 86400000 * 5), actor: 'System' }, { action: 'resolved', at: new Date(Date.now() - 86400000), actor: 'Admin' }], createdAt: new Date(Date.now() - 86400000 * 5), updatedAt: new Date(Date.now() - 86400000) },
      ]);
      results.disputes = 3;
    }

    // Notifications
    const notifCount = await db.collection('notifications').countDocuments({});
    if (notifCount === 0) {
      await db.collection('notifications').insertMany([
        { title: 'High Value Order Received', message: 'New gold order worth $125,000 from Global Steel Corp', type: 'order', read: false, createdAt: new Date() },
        { title: 'KYC Verification Required', message: '3 new KYC documents awaiting review', type: 'compliance', read: false, createdAt: new Date(Date.now() - 3600000) },
        { title: 'System Maintenance Scheduled', message: 'Platform maintenance window: March 5, 2:00 AM - 4:00 AM UTC', type: 'system', read: false, createdAt: new Date(Date.now() - 7200000) },
        { title: 'New User Registration Spike', message: '15 new user registrations in the last hour', type: 'info', read: true, createdAt: new Date(Date.now() - 86400000) },
        { title: 'Dispute Escalation', message: 'Dispute #ORD-002 has been escalated for management review', type: 'dispute', read: false, createdAt: new Date(Date.now() - 1800000) },
      ]);
      results.notifications = 5;
    }

    // Audit log
    const auditCount = await db.collection('audit_log').countDocuments({});
    if (auditCount === 0) {
      await db.collection('audit_log').insertMany([
        { action: 'Admin Login', type: 'auth', details: 'admin@mineralbridge.com logged in from 192.168.1.1', actor: 'Admin', createdAt: new Date() },
        { action: 'User KYC Approved', type: 'compliance', details: 'Approved KYC for user +91|9629299511', actor: 'Admin', targetType: 'user', createdAt: new Date(Date.now() - 3600000) },
        { action: 'Order Status Updated', type: 'order', details: 'Order ORD-001 moved to Processing', actor: 'Admin', targetType: 'order', createdAt: new Date(Date.now() - 7200000) },
        { action: 'System Settings Changed', type: 'admin', details: 'Updated CORS allowed origins', actor: 'Admin', targetType: 'settings', createdAt: new Date(Date.now() - 86400000) },
        { action: 'Dispute Created', type: 'dispute', details: 'New dispute opened for order ORD-002', actor: 'System', targetType: 'dispute', createdAt: new Date(Date.now() - 86400000 * 2) },
      ]);
      results.auditLog = 5;
    }

    // Banners
    const bannerCount = await db.collection('banners').countDocuments({});
    if (bannerCount === 0) {
      await db.collection('banners').insertMany([
        { title: 'Welcome to Mineral Bridge', imageUrl: '', targetPage: 'homepage', linkUrl: '', position: 0, active: true, clicks: 245, createdAt: new Date() },
        { title: 'Buy Premium Minerals', imageUrl: '', targetPage: 'buy', linkUrl: '', position: 1, active: true, clicks: 128, createdAt: new Date() },
        { title: 'Sell Your Minerals', imageUrl: '', targetPage: 'sell', linkUrl: '', position: 2, active: true, clicks: 89, createdAt: new Date() },
      ]);
      await bumpBannerCacheVersion(db);
      results.banners = 3;
    }

    // Shipments
    const shipCount = await db.collection('shipments').countDocuments({});
    if (shipCount === 0) {
      await db.collection('shipments').insertMany([
        { orderId: 'ORD-001', origin: 'Mumbai, India', destination: 'Dubai, UAE', carrier: 'DHL Express', mineral: 'Gold (Au 99.9%)', weight: '5 kg', value: 45000, status: 'in-transit', progress: 65, estimatedDelivery: new Date(Date.now() + 86400000 * 3), timeline: [{ status: 'created', at: new Date(Date.now() - 86400000 * 2), note: 'Shipment created' }, { status: 'in-transit', at: new Date(Date.now() - 86400000), note: 'Picked up by carrier' }], createdAt: new Date(Date.now() - 86400000 * 2), updatedAt: new Date() },
        { orderId: 'ORD-002', origin: 'Lubumbashi, DRC', destination: 'Antwerp, Belgium', carrier: 'Maersk', mineral: 'Cobalt (Co)', weight: '200 kg', value: 120000, status: 'in-transit', progress: 40, estimatedDelivery: new Date(Date.now() + 86400000 * 12), timeline: [{ status: 'created', at: new Date(Date.now() - 86400000 * 5), note: 'Shipment created' }], createdAt: new Date(Date.now() - 86400000 * 5), updatedAt: new Date() },
        { orderId: 'ORD-003', origin: 'Perth, Australia', destination: 'Shanghai, China', carrier: 'FedEx', mineral: 'Lithium Carbonate', weight: '500 kg', value: 85000, status: 'delivered', progress: 100, estimatedDelivery: new Date(Date.now() - 86400000), actualDelivery: new Date(Date.now() - 86400000), timeline: [{ status: 'created', at: new Date(Date.now() - 86400000 * 10), note: 'Shipment created' }, { status: 'delivered', at: new Date(Date.now() - 86400000), note: 'Delivered to consignee' }], createdAt: new Date(Date.now() - 86400000 * 10), updatedAt: new Date(Date.now() - 86400000) },
      ]);
      results.shipments = 3;
    }

    // Insurance
    const policyCount = await db.collection('insurance_policies').countDocuments({});
    if (policyCount === 0) {
      await db.collection('insurance_policies').insertMany([
        { orderId: 'ORD-001', provider: "Lloyd's of London", coverageType: 'transit', insuredValue: 50000, premium: 1500, status: 'active', expiresAt: new Date(Date.now() + 86400000 * 90), createdAt: new Date() },
        { orderId: 'ORD-002', provider: 'Allianz', coverageType: 'full', insuredValue: 130000, premium: 4200, status: 'active', expiresAt: new Date(Date.now() + 86400000 * 60), createdAt: new Date() },
        { orderId: 'ORD-003', provider: "Lloyd's of London", coverageType: 'transit', insuredValue: 90000, premium: 2700, status: 'expired', expiresAt: new Date(Date.now() - 86400000 * 5), createdAt: new Date(Date.now() - 86400000 * 100) },
      ]);
      results.policies = 3;
      await db.collection('insurance_claims').insertMany([
        { policyId: 'policy1', orderId: 'ORD-003', reason: 'Partial damage during transit', claimAmount: 8500, status: 'approved', payoutAmount: 8000, approvedAt: new Date(Date.now() - 86400000 * 2), timeline: [{ action: 'filed', at: new Date(Date.now() - 86400000 * 5), actor: 'System' }, { action: 'approved', at: new Date(Date.now() - 86400000 * 2), actor: 'Admin' }], createdAt: new Date(Date.now() - 86400000 * 5) },
        { policyId: 'policy2', orderId: 'ORD-002', reason: 'Suspected contamination during handling', claimAmount: 15000, status: 'pending', timeline: [{ action: 'filed', at: new Date(), actor: 'System' }], createdAt: new Date() },
      ]);
      results.claims = 2;
      await db.collection('insurance_providers').insertMany([
        { name: "Lloyd's of London", type: 'underwriter', contactEmail: 'minerals@lloyds.com', regions: ['Global'], coverageTypes: ['transit', 'storage', 'full'], active: true, createdAt: new Date() },
        { name: 'Allianz', type: 'underwriter', contactEmail: 'cargo@allianz.com', regions: ['Europe', 'Asia', 'Africa'], coverageTypes: ['transit', 'full'], active: true, createdAt: new Date() },
        { name: 'Local Insurers Network', type: 'broker', contactEmail: 'info@localinsure.com', regions: ['Africa', 'South America'], coverageTypes: ['transit'], active: true, createdAt: new Date() },
      ]);
      results.providers = 3;
    }

    // Testing labs
    const labCount = await db.collection('testing_labs').countDocuments({});
    if (labCount === 0) {
      await db.collection('testing_labs').insertMany([
        { name: 'SGS Mumbai', location: 'Mumbai, India', certifications: ['ISO 17025', 'LBMA'], turnaroundDays: 3, contactEmail: 'labs@sgs.com', minerals: ['Gold', 'Silver', 'Platinum'], active: true, createdAt: new Date() },
        { name: 'Bureau Veritas', location: 'Antwerp, Belgium', certifications: ['ISO 17025', 'KIMBERLEY'], turnaroundDays: 5, contactEmail: 'testing@bureauveritas.com', minerals: ['Diamonds', 'Cobalt', 'Tantalum'], active: true, createdAt: new Date() },
        { name: 'ALS Laboratories', location: 'Perth, Australia', certifications: ['ISO 17025', 'NATA'], turnaroundDays: 4, contactEmail: 'minerals@als.com', minerals: ['Lithium', 'Rare Earths', 'Iron Ore'], active: true, createdAt: new Date() },
      ]);
      results.testingLabs = 3;
      await db.collection('testing_orders').insertMany([
        { orderId: 'ORD-001', labName: 'SGS Mumbai', mineral: 'Gold (Au)', testType: 'purity', sampleWeight: '50g', status: 'in-progress', progress: 70, submittedAt: new Date(Date.now() - 86400000 * 2), createdAt: new Date(Date.now() - 86400000 * 2) },
        { orderId: 'ORD-002', labName: 'Bureau Veritas', mineral: 'Cobalt (Co)', testType: 'composition', sampleWeight: '200g', status: 'completed', progress: 100, results: { purity: '99.2%', grade: 'A' }, completedAt: new Date(Date.now() - 86400000), submittedAt: new Date(Date.now() - 86400000 * 6), createdAt: new Date(Date.now() - 86400000 * 6) },
      ]);
      results.testingOrders = 2;
    }

    // Admin roles
    const roleCount = await db.collection('admin_roles').countDocuments({});
    if (roleCount === 0) {
      await db.collection('admin_roles').insertMany([
        { name: 'CEO', permissions: { dashboard: true, users: true, orders: true, finance: true, compliance: true, disputes: true, content: true, analytics: true, partners: true, logistics: true, insurance: true, settings: true, audit: true }, description: 'Full platform access', createdAt: new Date() },
        { name: 'Operations Manager', permissions: { dashboard: true, users: true, orders: true, finance: false, compliance: true, disputes: true, content: false, analytics: true, partners: true, logistics: true, insurance: false, settings: false, audit: true }, description: 'Day-to-day operations management', createdAt: new Date() },
        { name: 'Compliance Officer', permissions: { dashboard: true, users: true, orders: false, finance: false, compliance: true, disputes: true, content: false, analytics: false, partners: false, logistics: false, insurance: false, settings: false, audit: true }, description: 'KYC and regulatory compliance', createdAt: new Date() },
        { name: 'Support Agent', permissions: { dashboard: true, users: true, orders: true, finance: false, compliance: false, disputes: false, content: false, analytics: false, partners: false, logistics: false, insurance: false, settings: false, audit: false }, description: 'Customer support and enquiry handling', createdAt: new Date() },
      ]);
      results.roles = 4;
    }

    // Integrations
    const intCount = await db.collection('admin_integrations').countDocuments({});
    if (intCount === 0) {
      await db.collection('admin_integrations').insertMany([
        { name: 'Stripe', type: 'payment', apiKey: '', webhookUrl: '', enabled: true, config: { mode: 'test' }, createdAt: new Date() },
        { name: 'SendGrid', type: 'email', apiKey: '', webhookUrl: '', enabled: true, config: {}, createdAt: new Date() },
        { name: 'Slack', type: 'notification', apiKey: '', webhookUrl: '', enabled: false, config: { channel: '#alerts' }, createdAt: new Date() },
        { name: 'Google Analytics', type: 'analytics', apiKey: '', webhookUrl: '', enabled: true, config: { trackingId: '' }, createdAt: new Date() },
      ]);
      results.integrations = 4;
    }

    // Facilities
    const facCount = await db.collection('facilities').countDocuments({});
    if (facCount === 0) {
      await db.collection('facilities').insertMany([
        { name: 'Osei Export Terminal', street: 'Industrial Loop 44A', city: 'Accra', state: 'Greater Accra', postalCode: 'GA-221', country: 'Ghana', phone: '+233 24 555 0192', email: 'terminal@oseimineral.com', status: 'Active', isPrimary: true, isSaved: true, permitNumber: 'GH-88219-X', addedVia: 'Dashboard', addedAt: new Date(), usageCount: { buy: 2, sell: 1 }, usageHistory: [] },
      ]);
      results.facilities = 1;
    }

    res.json({ message: 'Phase 3 seed complete', seeded: results });
  } catch (err) {
    console.error('Seed error:', err);
    res.status(500).json({ error: 'Seed failed' });
  }
});

// ──────────────────────────────────────────────
// FACILITIES (platform-wide delivery/processing sites)
// ──────────────────────────────────────────────

router.get('/facilities', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('facilities').find({}).sort({ name: 1 }).limit(100).toArray();
    res.json(list.map((f) => ({
      id: f._id.toString(),
      name: f.name || '',
      street: f.street || '',
      city: f.city || '',
      state: f.state || '',
      postalCode: f.postalCode || '',
      country: f.country || '',
      phone: f.phone || '',
      email: f.email || '',
      status: f.status || 'Active',
      isPrimary: Boolean(f.isPrimary),
      isSaved: Boolean(f.isSaved),
      permitNumber: f.permitNumber || '',
      addedVia: f.addedVia || 'Dashboard',
      addedAt: f.addedAt ? new Date(f.addedAt).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }) : '',
      usageCount: f.usageCount || { buy: 0, sell: 0 },
      usageHistory: f.usageHistory || [],
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch facilities' });
  }
});

router.post('/facilities', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { name, street, city, state, postalCode, country, phone, email, permitNumber } = req.body || {};
    if (!name || !country) return res.status(400).json({ error: 'name and country required' });
    const db = getDB();
    const doc = {
      name: String(name),
      street: street ? String(street) : '',
      city: city ? String(city) : '',
      state: state ? String(state) : '',
      postalCode: postalCode ? String(postalCode) : '',
      country: String(country),
      phone: phone ? String(phone) : '',
      email: email ? String(email) : '',
      status: 'Active',
      isPrimary: false,
      isSaved: true,
      permitNumber: permitNumber ? String(permitNumber) : '',
      addedVia: 'Dashboard',
      addedAt: new Date(),
      usageCount: { buy: 0, sell: 0 },
      usageHistory: [],
    };
    const result = await db.collection('facilities').insertOne(doc);
    const inserted = await db.collection('facilities').findOne({ _id: result.insertedId });
    res.status(201).json({
      id: inserted._id.toString(),
      ...doc,
      addedAt: doc.addedAt.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }),
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create facility' });
  }
});

router.delete('/facilities/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const result = await db.collection('facilities').deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Facility not found' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete facility' });
  }
});

// ──────────────────────────────────────────────
// CALL HISTORY (admin call/email logs)
// ──────────────────────────────────────────────

function mapCallHistoryToResponse(c) {
  const history = (c.conversationHistory || []).map((h) => ({
    at: h.at ? (typeof h.at === 'string' ? h.at : new Date(h.at).toISOString()) : new Date().toISOString(),
    note: h.note || '',
    conversationScenario: h.conversationScenario || '',
  }));
  return {
    id: c._id.toString(),
    phoneNumber: c.phoneNumber || '',
    normalizedPhone: c.normalizedPhone || (c.phoneNumber || '').replace(/\D/g, ''),
    orderId: c.orderId || undefined,
    userId: c.userId || undefined,
    userName: c.userName || '',
    contextLabel: c.contextLabel || '',
    at: c.at ? (typeof c.at === 'string' ? c.at : new Date(c.at).toISOString()) : new Date().toISOString(),
    note: c.note || '',
    admin: c.admin || '',
    teamMembers: c.teamMembers || (c.admin ? [c.admin] : []),
    conversationScenario: c.conversationScenario || '',
    callRecordingUrl: c.callRecordingUrl || '',
    contactMethod: c.contactMethod || 'Mobile',
    type: c.type || 'call',
    status: c.status === 'verified' ? 'verified' : 'pending',
    conversationHistory: history,
  };
}

router.get('/call-history', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const list = await db.collection('call_history').find({}).sort({ at: -1 }).limit(5000).toArray();
    res.json(list.map(mapCallHistoryToResponse));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch call history' });
  }
});

router.post('/call-history', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { phoneNumber, orderId, userId, userName, contextLabel, note, admin, teamMembers, conversationScenario, callRecordingUrl, contactMethod, type, status } = req.body || {};
    if (!phoneNumber) return res.status(400).json({ error: 'phoneNumber required' });
    const normalized = String(phoneNumber).replace(/\D/g, '');
    const db = getDB();
    const adminName = admin || (req.user && req.user.name) || 'Admin';
    const doc = {
      phoneNumber: String(phoneNumber),
      normalizedPhone: normalized,
      orderId: orderId || null,
      userId: userId || null,
      userName: userName || '',
      contextLabel: contextLabel || '',
      at: new Date(),
      note: note || '',
      admin: adminName,
      teamMembers: Array.isArray(teamMembers) ? teamMembers : (teamMembers ? [teamMembers] : [adminName]),
      conversationScenario: conversationScenario || '',
      callRecordingUrl: callRecordingUrl || '',
      contactMethod: contactMethod === 'Email' ? 'Email' : 'Mobile',
      type: type === 'email' ? 'email' : 'call',
      status: status === 'verified' ? 'verified' : 'pending',
    };
    const result = await db.collection('call_history').insertOne(doc);
    const inserted = await db.collection('call_history').findOne({ _id: result.insertedId });
    res.status(201).json(mapCallHistoryToResponse(inserted));
  } catch (err) {
    res.status(500).json({ error: 'Failed to create call history entry' });
  }
});

router.patch('/call-history/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid call history id' });
    const { note, admin, teamMembers, conversationScenario, callRecordingUrl, status } = req.body || {};
    const db = getDB();
    const updates = {};
    if (note !== undefined) updates.note = String(note);
    if (admin !== undefined) updates.admin = String(admin);
    if (teamMembers !== undefined) updates.teamMembers = Array.isArray(teamMembers) ? teamMembers : [teamMembers];
    if (conversationScenario !== undefined) updates.conversationScenario = String(conversationScenario);
    if (callRecordingUrl !== undefined) updates.callRecordingUrl = String(callRecordingUrl);
    if (status === 'verified' || status === 'pending') updates.status = status;
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No fields to update' });
    const entry = await db.collection('call_history').findOne({ _id: new ObjectId(id) });
    if (!entry) return res.status(404).json({ error: 'Call history entry not found' });
    const updateOp = { $set: updates };
    if (note !== undefined || conversationScenario !== undefined) {
      const prevNote = entry.note != null ? String(entry.note) : '';
      const prevScenario = entry.conversationScenario != null ? String(entry.conversationScenario) : '';
      if (prevNote || prevScenario) {
        updateOp.$push = {
          conversationHistory: {
            at: new Date(),
            note: prevNote,
            conversationScenario: prevScenario,
          },
        };
      }
    }
    const result = await db.collection('call_history').findOneAndUpdate(
      { _id: new ObjectId(id) },
      updateOp,
      { returnDocument: 'after' }
    );
    if (!result) return res.status(404).json({ error: 'Call history entry not found' });
    if (status === 'verified' && entry.orderId) {
      const oid = String(entry.orderId).trim();
      let orderFilter;
      if (ObjectId.isValid(oid)) {
        orderFilter = { _id: new ObjectId(oid) };
      } else {
        orderFilter = { orderId: oid };
      }
      const orderDoc = await db.collection('orders').findOne(orderFilter).catch(() => null);
      if (orderDoc) {
        const now = new Date();
        const orderType = (orderDoc.type || '').toLowerCase();
        const currentStatus = orderDoc.status || '';
        // When marking contact verified, advance from "Awaiting Team Contact" to next step so pipeline and progress UI update
        const nextStatus =
          currentStatus === 'Awaiting Team Contact'
            ? (orderType === 'sell' ? 'Sample Test Required' : 'Price Confirmed')
            : null;
        const updateFields = {
          contactVerified: true,
          contactVerifiedAt: now,
          updatedAt: now,
        };
        if (nextStatus) {
          updateFields.status = nextStatus;
          // Ensure timeline has a step entry for the new status (dashboard uses timeline for display)
          const timeline = Array.isArray(orderDoc.timeline) ? [...orderDoc.timeline] : [];
          const stepLabel = nextStatus;
          if (!timeline.some((t) => t && (t.label === stepLabel || t.step !== undefined))) {
            const stepIndex = orderType === 'sell'
              ? { 'Order Submitted': 1, 'Awaiting Team Contact': 2, 'Sample Test Required': 3, 'Price Confirmed': 4, 'Payment Initiated': 5, 'Order Completed': 6 }[nextStatus]
              : { 'Order Submitted': 1, 'Awaiting Team Contact': 2, 'Price Confirmed': 3, 'Payment Initiated': 4, 'Order Completed': 5 }[nextStatus];
            if (stepIndex) timeline.push({ step: stepIndex, label: stepLabel, at: now });
          }
          updateFields.timeline = timeline;
        }
        await db.collection('orders').updateOne(
          { _id: orderDoc._id },
          { $set: updateFields }
        ).catch(() => {});
      }
    }
    res.json(mapCallHistoryToResponse(result));
  } catch (err) {
    res.status(500).json({ error: 'Failed to update call history' });
  }
});

router.delete('/call-history/:id', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'Invalid call history id' });
    const db = getDB();
    const result = await db.collection('call_history').deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Call history entry not found' });
    }
    res.json({ success: true, deleted: true, id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete call history entry' });
  }
});

// ──────────────────────────────────────────────
// COMPLIANCE VERIFICATIONS (KYC + users aggregated)
// ──────────────────────────────────────────────

router.get('/compliance/verifications', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const kycList = await db.collection('kyc_documents').find({}).sort({ createdAt: -1 }).limit(100).toArray();
    const userIds = [...new Set(kycList.map((k) => k.userId).filter(Boolean))];
    const validIds = userIds.filter((id) => ObjectId.isValid(id)).map((id) => new ObjectId(id));
    const users = validIds.length ? await db.collection('users').find({ _id: { $in: validIds } }).toArray() : [];
    const userMap = {};
    users.forEach((u) => { userMap[u._id.toString()] = u; });
    const profiles = await db.collection('profiles').find({ userId: { $in: userIds } }).toArray();
    const profileMap = {};
    profiles.forEach((p) => { profileMap[p.userId] = p; });
    const verifications = [];
    const seen = new Set();
    for (const k of kycList) {
      const key = k.userId || k._id.toString();
      if (seen.has(key)) continue;
      seen.add(key);
      const user = userMap[k.userId];
      const profile = profileMap[k.userId];
      const name = user ? (user.name || user.email || user.phone || 'Unknown') : 'Unknown';
      const status = k.status === 'approved' ? 'Approved' : k.status === 'rejected' ? 'Rejected' : k.status === 'flagged' ? 'Flagged' : 'Pending';
      verifications.push({
        id: k._id.toString(),
        name,
        type: profile && profile.kycType ? (profile.kycType === 'business' ? 'Business' : profile.kycType === 'miner' ? 'Miner' : 'Individual') : 'Individual',
        status,
        score: status === 'Approved' ? 85 + Math.floor(Math.random() * 15) : status === 'Rejected' ? 40 + Math.floor(Math.random() * 20) : 70 + Math.floor(Math.random() * 15),
        country: (user && user.countryCode) || '—',
        countryName: (user && user.countryCode) ? user.countryCode : '—',
        docs: 1,
        totalDocs: 1,
        issues: status === 'Rejected' ? ['Document rejected'] : status === 'Pending' ? [] : [],
        updated: k.updatedAt || k.createdAt ? (() => { const d = new Date(k.updatedAt || k.createdAt); const diff = Date.now() - d.getTime(); if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`; if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`; return `${Math.floor(diff / 86400000)}d ago`; })() : '—',
        avatar: name.split(' ').map((n) => n[0]).join('').slice(0, 2).toUpperCase() || '—',
      });
    }
    res.json(verifications);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch compliance verifications' });
  }
});

router.get('/compliance/alerts', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const kycRejected = await db.collection('kyc_documents').find({ status: { $in: ['rejected', 'flagged'] } }).sort({ updatedAt: -1 }).limit(20).toArray();
    const userIds = kycRejected.map((k) => k.userId).filter((id) => id && ObjectId.isValid(id));
    const userObjIds = userIds.map((id) => new ObjectId(id));
    const users = userObjIds.length ? await db.collection('users').find({ _id: { $in: userObjIds } }).toArray() : [];
    const userMap = {};
    users.forEach((u) => { userMap[u._id.toString()] = u; });
    const alerts = kycRejected.map((k) => {
      const user = userMap[k.userId];
      const entity = user ? (user.name || user.email || user.phone || 'Unknown') : 'Unknown';
      return {
        id: k._id.toString(),
        entity,
        issue: k.status === 'rejected' ? 'Document rejected' : 'KYC flagged for review',
        status: 'Open',
        admin: '—',
      };
    });
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch compliance alerts' });
  }
});

// ──────────────────────────────────────────────
// HELP & DOCUMENTATION (Dashboard admin help)
// ──────────────────────────────────────────────

const DEFAULT_DASHBOARD_FAQS = [
  { id: '1', q: 'How do I release a payment for a transaction?', a: 'Go to Financial & Reporting → Transactions, open the transaction, and follow the 6-step flow (Send QR → Call Buyer → Reserve Escrow → Testing → LC Issued → Release Payment). Complete the Release step to mark the payment as released.' },
  { id: '2', q: 'Where can I see all activity and audit trail?', a: 'Use the Audit & Activity Log from the sidebar (under Settings) or from the dashboard. It shows app and dashboard actions with links to related orders, transactions, and users.' },
  { id: '3', q: 'How do I change my admin profile or password?', a: 'Click your avatar in the header → My Account. There you can update your name, email, and password. Changes are saved to the admin registry and persist across sessions.' },
  { id: '4', q: 'How do I filter financial data by date?', a: 'On the Financial & Reporting page, use the Date range dropdown (e.g. Jan 2026, Feb 2026, YTD 2026). Metrics and transaction lists are filtered by the selected range.' },
  { id: '5', q: 'Can I export transactions in bulk?', a: 'Yes. On the Transactions page (Financial & Reporting → Transactions), select rows using the checkboxes, then use Bulk export (CSV) to download the selected transactions.' },
  { id: '6', q: 'How do I send an email or SMS to a user?', a: 'From Enquiry & Support, open an enquiry and use the reply or send options. From User Management you can trigger email/SMS where the UI offers it. These actions are logged in the Audit log.' },
];

const DEFAULT_QUICK_LINKS = [
  { id: '1', icon: 'Gem', label: 'Buy Management & Sell Management', description: 'List and manage minerals and sell submissions.' },
  { id: '2', icon: 'DollarSign', label: 'Orders & Settlements and Financial & Reporting', description: 'Orders, transactions, 6-step flow, revenue, and PDF export.' },
  { id: '3', icon: 'MessageSquare', label: 'Enquiry & Support', description: 'Replies and email/SMS actions are linked to users and logged in Audit log.' },
  { id: '4', icon: 'ShieldCheck', label: 'Compliance & Verification and User Management', description: 'KYC, verification, and user status.' },
];

router.get('/help/faqs', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const stored = await db.collection('dashboard_help_faqs').find({}).sort({ order: 1 }).toArray();
    const list = stored.length > 0
      ? stored.map((f) => ({ id: f._id?.toString(), q: f.question || f.q, a: f.answer || f.a }))
      : DEFAULT_DASHBOARD_FAQS;
    res.json(list);
  } catch (err) {
    res.json(DEFAULT_DASHBOARD_FAQS);
  }
});

router.get('/help/quick-links', authMiddleware, requireDashboard, async (req, res) => {
  try {
    const db = getDB();
    const stored = await db.collection('dashboard_help_quick_links').find({}).sort({ order: 1 }).toArray();
    const list = stored.length > 0
      ? stored.map((f) => ({ id: f._id?.toString(), icon: f.icon, label: f.label, description: f.description }))
      : DEFAULT_QUICK_LINKS;
    res.json(list);
  } catch (err) {
    res.json(DEFAULT_QUICK_LINKS);
  }
});

module.exports = router;
