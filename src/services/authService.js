const { SiweMessage } = require("siwe");
const { randomUUID } = require("crypto");
const { loadDb, saveDb } = require("../db/store");

// In-memory nonce store mapped to wallet addresses to prevent replay attacks
const nonces = new Map();

/**
 * Generates a standard cryptographic SIWE nonce
 * @param {string} walletAddress 
 */
async function createNonce(walletAddress) {
  const normalizedAddress = walletAddress.toLowerCase();
  
  // Use a secure crypto utility or standard random string for SIWE nonces
  const nonce = randomUUID().replace(/-/g, "").substring(0, 16);
  
  // Save nonce context for verification step
  nonces.set(normalizedAddress, nonce);
  
  return { nonce };
}

/**
 * Validates a SIWE message signature and handles backend database session allocation
 * @param {string} message 
 * @param {string} signature 
 */
async function verifySiwe(message, signature) {
  try {
    const siweMessage = new SiweMessage(message);
    
    // Cryptographically verify the signature against the message contents
    const verification = await siweMessage.verify({ signature });
    
    if (!verification.success) {
      throw new Error("Cryptographic signature verification failed.");
    }

    const walletAddress = siweMessage.address.toLowerCase();
    const storedNonce = nonces.get(walletAddress);

    // Validate that the nonce matches and came from our server
    if (!storedNonce || siweMessage.nonce !== storedNonce) {
      throw new Error("Invalid or expired session nonce.");
    }

    // Consume the nonce so it can't be reused
    nonces.delete(walletAddress);

    // Access the embedded database mock store
    const db = await loadDb();
    
    // Create or locate the user account profile record
    let user = db.users?.find(u => u.wallet_address.toLowerCase() === walletAddress);
    if (!user) {
      user = {
        id: randomUUID(),
        wallet_address: walletAddress,
        email: null,
        settings: {},
        created_at: new Date().toISOString()
      };
      if (!db.users) db.users = [];
      db.users.push(user);
    }

    // Allocate a fresh backend data session
    const session = {
      id: randomUUID(),
      user_id: user.id,
      wallet_address: walletAddress,
      email: user.email,
      settings: user.settings,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hour session
    };

    if (!db.sessions) db.sessions = [];
    db.sessions.push(session);
    await saveDb();

    // Note: The middleware router handles parsing this data to generate JWT tokens or secure cookies
    return { 
      success: true, 
      token: session.id, // Using session ID as the authentication token context
      user: { id: user.id, wallet: walletAddress } 
    };

  } catch (error) {
    throw new Error(`Authentication Error: ${error.message}`);
  }
}

/**
 * Retrieves an active active session based on the unique user identity reference
 * @param {string} userIdOrSub 
 */
async function getSession(userIdOrSub) {
  const db = await loadDb();
  if (!db.sessions) return null;
  
  // Find matching session that has not expired
  return db.sessions.find(s => 
    (s.id === userIdOrSub || s.user_id === userIdOrSub) && 
    new Date(s.expires_at) > new Date()
  );
}

/**
 * Destroys/invalidates an existing database session token context on logout
 * @param {string} userIdOrSub 
 */
async function invalidateSession(userIdOrSub) {
  const db = await loadDb();
  if (!db.sessions) return;
  
  // Purge the current session record from data arrays
  db.sessions = db.sessions.filter(s => s.id !== userIdOrSub && s.user_id !== userIdOrSub);
  await saveDb();
}

module.exports = {
  createNonce,
  verifySiwe,
  getSession,
  invalidateSession,
};