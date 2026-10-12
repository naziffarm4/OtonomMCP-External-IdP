import * as crypto from 'crypto';
import {
    AccountManager,
    ExternalIdPCore,
    SQLiteRelationalStore,
    JwtService,
    WebAuthnManager,
    ApprovalManager,
    User
} from './index';

describe('Account Management', () => {
    let manager: AccountManager;

    beforeEach(() => {
        manager = new AccountManager();
    });

    test('should register a new user successfully', async () => {
        const user = await manager.registerUser('testuser', 'hash123');
        expect(user.id).toBeDefined();
        expect(user.username).toBe('testuser');
    });

    test('should enforce unique user identities', async () => {
        await manager.registerUser('testuser', 'hash123');
        await expect(manager.registerUser('testuser', 'hash456')).rejects.toThrow('User identity must be unique');
    });

    test('should authenticate user and return session', async () => {
        await manager.registerUser('authuser', 'secret');
        const session = await manager.authenticate('authuser', 'secret');
        expect(session.id).toBeDefined();
        expect(session.token).toBeDefined();
        expect(session.userId).toBeDefined();
    });

    test('should fail authentication for invalid credentials', async () => {
        await manager.registerUser('authuser', 'secret');
        await expect(manager.authenticate('authuser', 'wrongsecret')).rejects.toThrow('Invalid credentials');
    });

    test('should verify valid session', async () => {
        await manager.registerUser('authuser', 'secret');
        const session = await manager.authenticate('authuser', 'secret');
        const isValid = await manager.verifySession(session.token);
        expect(isValid).toBe(true);
    });

    test('should reject invalid session', async () => {
        const isValid = await manager.verifySession('invalid-token');
        expect(isValid).toBe(false);
    });

    test('should update user profile successfully', async () => {
        const user = await manager.registerUser('profileuser', 'hash123', { displayName: 'Initial Name' });
        const updatedUser = await manager.updateProfile(user.id, { displayName: 'Updated Name', email: 'test@example.com' });
        expect(updatedUser.profile.displayName).toBe('Updated Name');
        expect(updatedUser.profile.email).toBe('test@example.com');
    });

    test('should fail updating profile for non-existent user', async () => {
        await expect(manager.updateProfile('non-existent-id', { displayName: 'Name' })).rejects.toThrow('User not found');
    });

    test('should retrieve user by id', async () => {
        const user = await manager.registerUser('getuser', 'pass');
        const retrieved = await manager.getUser(user.id);
        expect(retrieved).toBeDefined();
        expect(retrieved?.username).toBe('getuser');
    });

    test('should return undefined when retrieving non-existent user', async () => {
        const retrieved = await manager.getUser('non-existent-id');
        expect(retrieved).toBeUndefined();
    });

    test('should reject expired session', async () => {
        jest.useFakeTimers();
        try {
            await manager.registerUser('timetest', 'pass');
            const session = await manager.authenticate('timetest', 'pass');
            expect(await manager.verifySession(session.token)).toBe(true);
            
            // Advance time past 1 hour (3600000 ms)
            jest.advanceTimersByTime(3600000 + 1000);
            expect(await manager.verifySession(session.token)).toBe(false);
        } finally {
            jest.useRealTimers();
        }
    });
});

describe('SQLite Relational Storage Layer (ARCH-DEC-002, AC-C725C33A)', () => {
    let store: SQLiteRelationalStore;

    beforeEach(() => {
        store = new SQLiteRelationalStore();
    });

    test('should identify as SQLite relational database', () => {
        expect(store.storageEngine).toContain('SQLite relational database');
    });

    test('should enforce primary key uniqueness', async () => {
        const user: User = { id: 'usr-1', username: 'alice', passwordHash: 'hash', profile: {} };
        await store.insert('users', user);
        await expect(store.insert('users', { ...user, username: 'alice2' })).rejects.toThrow('PRIMARY KEY constraint failed');
    });

    test('should enforce foreign key constraint on sessions', async () => {
        await expect(store.insert('sessions', {
            id: 'sess-1',
            userId: 'non-existent-user',
            token: 'tok-1',
            expiresAt: Date.now() + 10000
        })).rejects.toThrow('FOREIGN KEY constraint failed: sessions.userId');
    });

    test('should support transactional atomic rollback on failure', async () => {
        await store.insert('users', { id: 'usr-base', username: 'baseuser', passwordHash: 'pass', profile: {} });

        await expect(store.transaction(async () => {
            await store.insert('users', { id: 'usr-temp', username: 'tempuser', passwordHash: 'pass', profile: {} });
            // Intentionally cause failure:
            throw new Error('Database transaction abort');
        })).rejects.toThrow('Database transaction abort');

        const tempUser = await store.findById('users', 'usr-temp');
        expect(tempUser).toBeUndefined();

        const baseUser = await store.findById('users', 'usr-base');
        expect(baseUser).toBeDefined();
    });
});

describe('Cryptographic JWT Service (AC-581780C6)', () => {
    let jwtService: JwtService;

    beforeEach(() => {
        jwtService = new JwtService('test-secret-key-at-least-32-chars-long');
    });

    test('should sign and successfully verify a JWT', () => {
        const token = jwtService.sign({ sub: 'user-123', role: 'admin' });
        expect(typeof token).toBe('string');

        const payload = jwtService.verify(token);
        expect(payload.sub).toBe('user-123');
        expect(payload.role).toBe('admin');
        expect(payload.iss).toBe('OtonomMCP-External-IdP');
        expect(payload.aud).toBe('OtonomMCP');
        expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    });

    test('should reject tampered JWT signatures', () => {
        const token = jwtService.sign({ sub: 'user-123' });
        const parts = token.split('.');
        const tampered = `${parts[0]}.${parts[1]}.tamperedSignatureValue`;

        expect(() => jwtService.verify(tampered)).toThrow('Invalid token signature');
        expect(jwtService.isValid(tampered)).toBe(false);
    });

    test('should reject expired tokens', () => {
        const token = jwtService.sign({ sub: 'user-123' }, -10); // Expired 10 seconds ago
        expect(() => jwtService.verify(token)).toThrow('Token expired');
        expect(jwtService.isValid(token)).toBe(false);
    });

    test('should maintain >99% token verification rate under test workload (AC-581780C6)', () => {
        const total = 500;
        let successful = 0;

        for (let i = 0; i < total; i++) {
            const token = jwtService.sign({ sub: `user-${i}`, testIndex: i });
            if (jwtService.isValid(token)) {
                successful++;
            }
        }

        const rate = (successful / total) * 100;
        expect(rate).toBeGreaterThanOrEqual(99.0);
    });
});

describe('WebAuthn Passkey Manager', () => {
    let store: SQLiteRelationalStore;
    let webauthn: WebAuthnManager;
    let keyPair: { publicKey: string; privateKey: string };

    beforeEach(async () => {
        store = new SQLiteRelationalStore();
        webauthn = new WebAuthnManager(store);
        await store.insert('users', { id: 'usr-webauthn', username: 'webauthn_user', passwordHash: 'hash', profile: {} });

        // Generate standard P-256 ECDSA key pair used in WebAuthn
        keyPair = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
    });

    test('should generate and store cryptographic challenges', async () => {
        const challenge = await webauthn.generateChallenge('usr-webauthn');
        expect(challenge).toBeDefined();
        expect(challenge.length).toBeGreaterThan(16);
    });

    test('should register a WebAuthn passkey credential', async () => {
        const cred = await webauthn.registerCredential('usr-webauthn', 'cred-12345', keyPair.publicKey);
        expect(cred.id).toBeDefined();
        expect(cred.userId).toBe('usr-webauthn');
        expect(cred.credentialId).toBe('cred-12345');
        expect(cred.publicKey).toBe(keyPair.publicKey);
        expect(cred.counter).toBe(0);
    });

    test('should verify valid passkey assertion signature', async () => {
        await webauthn.registerCredential('usr-webauthn', 'cred-sig-test', keyPair.publicKey);
        const challenge = await webauthn.generateChallenge('usr-webauthn');

        // Sign challenge with private key (standard ECDSA-SHA256 assertion)
        const signer = crypto.createSign('SHA256');
        signer.update(challenge);
        const signatureBase64 = signer.sign(keyPair.privateKey, 'base64');

        const isValid = await webauthn.verifyAssertion('cred-sig-test', challenge, signatureBase64);
        expect(isValid).toBe(true);

        // Challenge should be single-use (replay prevention)
        const replayed = await webauthn.verifyAssertion('cred-sig-test', challenge, signatureBase64);
        expect(replayed).toBe(false);
    });

    test('should reject invalid assertion signature', async () => {
        await webauthn.registerCredential('usr-webauthn', 'cred-invalid', keyPair.publicKey);
        const challenge = await webauthn.generateChallenge('usr-webauthn');

        const isVerified = await webauthn.verifyAssertion('cred-invalid', challenge, 'invalidBase64Signature==');
        expect(isVerified).toBe(false);
    });
});

describe('OtonomMCP Approval Context Inspection & Human Decision Workflow (BR-369628EF, AC-D45B8437)', () => {
    let store: SQLiteRelationalStore;
    let jwtService: JwtService;
    let approvalManager: ApprovalManager;

    beforeEach(async () => {
        store = new SQLiteRelationalStore();
        jwtService = new JwtService();
        approvalManager = new ApprovalManager(store, jwtService);
        await store.insert('users', { id: 'usr-reviewer', username: 'reviewer1', passwordHash: 'hash', profile: {} });
    });

    test('should create and inspect approval request with detailed context', async () => {
        const request = await approvalManager.createRequest(
            'dir-sess-123',
            'DEPLOY_RELEASE',
            {
                summary: 'Deploy v2.0 to production',
                riskLevel: 'HIGH',
                affectedFiles: ['src/index.ts', 'package.json'],
                targetEnvironment: 'production'
            }
        );

        expect(request.id).toBeDefined();
        expect(request.status).toBe('PENDING');

        // Context inspection by human reviewer
        const inspected = await approvalManager.inspectApprovalContext(request.id);
        expect(inspected.action).toBe('DEPLOY_RELEASE');
        expect(inspected.context.riskLevel).toBe('HIGH');
        expect(inspected.context.summary).toBe('Deploy v2.0 to production');
    });

    test('should approve request and issue cryptographic decision token upon biometric confirmation', async () => {
        const request = await approvalManager.createRequest(
            'dir-sess-123',
            'EXECUTE_COMMAND',
            { command: 'npm publish', riskLevel: 'HIGH' }
        );

        const result = await approvalManager.approveRequest(request.id, 'usr-reviewer', true);
        expect(result.request.status).toBe('APPROVED');
        expect(result.request.approvedBy).toBe('usr-reviewer');
        expect(result.request.decidedAt).toBeDefined();
        expect(result.decisionToken).toBeDefined();

        // Verify decision token claims
        const claims = jwtService.verify(result.decisionToken);
        expect(claims.sub).toBe('usr-reviewer');
        expect(claims.decision).toBe('APPROVED');
        expect(claims.requestId).toBe(request.id);
        expect(claims.biometricVerified).toBe(true);
    });

    test('should reject approval request if biometric verification is not confirmed', async () => {
        const request = await approvalManager.createRequest('dir-sess-123', 'SENSITIVE_ACTION', {});
        await expect(approvalManager.approveRequest(request.id, 'usr-reviewer', false))
            .rejects.toThrow('Biometric passkey verification is required');
    });

    test('should reject approval request with reason', async () => {
        const request = await approvalManager.createRequest('dir-sess-123', 'DROP_DATABASE', { riskLevel: 'CRITICAL' });
        const rejected = await approvalManager.rejectRequest(request.id, 'usr-reviewer', 'Risk unacceptable in production');

        expect(rejected.status).toBe('REJECTED');
        expect(rejected.rejectionReason).toBe('Risk unacceptable in production');
        expect(rejected.decidedAt).toBeDefined();
    });

    test('should reject state transitions on already decided requests', async () => {
        const request = await approvalManager.createRequest('dir-sess-123', 'TEST_ACTION', {});
        await approvalManager.approveRequest(request.id, 'usr-reviewer', true);

        await expect(approvalManager.approveRequest(request.id, 'usr-reviewer', true))
            .rejects.toThrow("Cannot approve request in status 'APPROVED'");
        await expect(approvalManager.rejectRequest(request.id, 'usr-reviewer', 'too late'))
            .rejects.toThrow("Cannot reject request in status 'APPROVED'");
    });
});

describe('Core External IdP Engine & Conformance Criteria (AC-7ED0AA8B, AC-8D6F007F, AC-061590F0, AC-9F2B307D)', () => {
    let idp: ExternalIdPCore;

    beforeEach(() => {
        idp = new ExternalIdPCore();
    });

    test('should operate as typed in-process module without external HTTP servers (AC-8D6F007F)', () => {
        expect(idp).toBeInstanceOf(ExternalIdPCore);
        expect(idp.accounts).toBeInstanceOf(AccountManager);
        expect(idp.webauthn).toBeInstanceOf(WebAuthnManager);
        expect(idp.approvals).toBeInstanceOf(ApprovalManager);
        expect(idp.jwt).toBeInstanceOf(JwtService);
        expect(idp.store.storageEngine).toContain('SQLite relational database');
    });

    test('should satisfy operational healthcheck response in < 5s (AC-061590F0)', async () => {
        const start = Date.now();
        const health = await idp.healthcheck();
        const elapsedMs = Date.now() - start;

        expect(health.status).toBe('OK');
        expect(health.storage).toContain('SQLite');
        expect(elapsedMs).toBeLessThan(5000); // Strict conformance to < 5s healthcheck
    });

    test('should satisfy latency < 200ms round-trip (AC-9F2B307D)', async () => {
        const start = Date.now();
        await idp.accounts.registerUser('perf_user', 'hash');
        const session = await idp.accounts.authenticate('perf_user', 'hash');
        await idp.accounts.verifySession(session.token);
        const elapsedMs = Date.now() - start;

        expect(elapsedMs).toBeLessThan(200);
    });

    test('should execute complete end-to-end human biometric approval workflow', async () => {
        // 1. Register human user
        const user = await idp.accounts.registerUser('human_admin', 'sec_pass');

        // 2. Register WebAuthn passkey
        const keyPair = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1',
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        await idp.webauthn.registerCredential(user.id, 'passkey-admin-1', keyPair.publicKey);

        // 3. OtonomMCP creates approval request
        const req = await idp.requestApproval('dir-sess-main', 'EXECUTE_CRITICAL_PATCH', {
            affectedService: 'AuthService',
            risk: 'HIGH',
            summary: 'Apply security patch'
        });

        // 4. Human inspects approval context
        const inspected = await idp.inspectContext(req.id);
        expect(inspected.context.risk).toBe('HIGH');

        // 5. Biometric challenge issued & signed with passkey
        const challenge = await idp.webauthn.generateChallenge(user.id);
        const signer = crypto.createSign('SHA256');
        signer.update(challenge);
        const signatureBase64 = signer.sign(keyPair.privateKey, 'base64');

        // 6. Authorize with passkey
        const { request: approvedReq, decisionToken } = await idp.authorizeWithPasskey(
            req.id,
            user.id,
            'passkey-admin-1',
            challenge,
            signatureBase64
        );

        expect(approvedReq.status).toBe('APPROVED');
        expect(decisionToken).toBeDefined();

        // 7. Verify decision token
        const verification = idp.verifyDecisionToken(decisionToken);
        expect(verification.valid).toBe(true);
        expect(verification.payload?.decision).toBe('APPROVED');
        expect(verification.payload?.sub).toBe(user.id);
        expect(verification.payload?.biometricVerified).toBe(true);
    });

    test('should provide Web Application Interface HTML with passkey and approval elements (AC-E7AF4CA8)', () => {
        const html = idp.getWebInterfaceHtml();
        expect(html).toBeDefined();
        expect(html.length).toBeGreaterThan(100);
        expect(html).toContain('OtonomMCP External IdP');
        expect(html).toContain('WebAuthn Biometric Passkeys');
        expect(html).toContain('Pending Human Gatekeeper Approvals');
        expect(html).toContain('healthBadge');
        expect(html).toContain('registerPasskey');
        expect(html).toContain('approveWithPasskey');
    });
});
