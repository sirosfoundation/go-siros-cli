package fido2

import "fmt"

// generateRegistrationHTML generates the HTML page for WebAuthn registration.
func generateRegistrationHTML(optsJSON, state string, port int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>WebAuthn Registration</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
        }
        .status {
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .waiting { background: #e3f2fd; }
        .success { background: #e8f5e9; }
        .error { background: #ffebee; }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <h1>🔐 WebAuthn Registration</h1>
    <div id="status" class="status waiting">
        <div class="spinner"></div>
        <p>Please follow your browser's security key prompt...</p>
    </div>
    <script>
        const opts = %s;
        const state = %q;
        const callbackUrl = 'http://127.0.0.1:%d/callback';

        // Decode base64url values
        function b64urlDecode(str) {
            str = str.replace(/-/g, '+').replace(/_/g, '/');
            while (str.length %% 4) str += '=';
            return Uint8Array.from(atob(str), c => c.charCodeAt(0));
        }
        
        function b64urlEncode(buf) {
            return btoa(String.fromCharCode(...new Uint8Array(buf)))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        async function register() {
            const statusEl = document.getElementById('status');
            try {
                // Prepare options
                const createOptions = {
                    publicKey: {
                        challenge: b64urlDecode(opts.challenge),
                        rp: opts.rp,
                        user: {
                            id: b64urlDecode(opts.user.id),
                            name: opts.user.name,
                            displayName: opts.user.displayName
                        },
                        pubKeyCredParams: opts.pubKeyCredParams,
                        authenticatorSelection: opts.authenticatorSelection,
                        attestation: opts.attestation || 'none',
                        extensions: {
                            prf: opts.extensions?.prf ? {} : undefined
                        }
                    }
                };

                // Create credential
                const credential = await navigator.credentials.create(createOptions);
                
                // Check for PRF support
                const prfSupported = credential.getClientExtensionResults?.()?.prf?.enabled || false;

                // Send result back
                const result = {
                    state: state,
                    credentialId: b64urlEncode(credential.rawId),
                    publicKey: b64urlEncode(credential.response.getPublicKey()),
                    authData: b64urlEncode(credential.response.getAuthenticatorData()),
                    clientDataJSON: b64urlEncode(credential.response.clientDataJSON),
                    prfSupported: prfSupported
                };

                const resp = await fetch(callbackUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(result)
                });

                statusEl.className = 'status success';
                statusEl.innerHTML = '<h2>✅ Registration Successful!</h2><p>You can close this window.</p>';
            } catch (err) {
                console.error('Registration failed:', err);
                
                await fetch(callbackUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({state: state, error: err.message || err.toString()})
                });

                statusEl.className = 'status error';
                statusEl.innerHTML = '<h2>❌ Registration Failed</h2><p>' + (err.message || err) + '</p>';
            }
        }

        register();
    </script>
</body>
</html>`, optsJSON, state, port)
}

// generateAuthenticationHTML generates the HTML page for WebAuthn authentication.
func generateAuthenticationHTML(optsJSON, state string, port int) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>WebAuthn Authentication</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            text-align: center;
        }
        .status {
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .waiting { background: #e3f2fd; }
        .success { background: #e8f5e9; }
        .error { background: #ffebee; }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <h1>🔐 WebAuthn Authentication</h1>
    <div id="status" class="status waiting">
        <div class="spinner"></div>
        <p>Please follow your browser's security key prompt...</p>
    </div>
    <script>
        const opts = %s;
        const state = %q;
        const callbackUrl = 'http://127.0.0.1:%d/callback';

        // Decode base64url values
        function b64urlDecode(str) {
            str = str.replace(/-/g, '+').replace(/_/g, '/');
            while (str.length %% 4) str += '=';
            return Uint8Array.from(atob(str), c => c.charCodeAt(0));
        }
        
        function b64urlEncode(buf) {
            return btoa(String.fromCharCode(...new Uint8Array(buf)))
                .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        async function authenticate() {
            const statusEl = document.getElementById('status');
            try {
                // Prepare options
                const getOptions = {
                    publicKey: {
                        challenge: b64urlDecode(opts.challenge),
                        rpId: opts.rpId,
                        userVerification: opts.userVerification || 'preferred',
                        allowCredentials: (opts.allowCredentials || []).map(c => ({
                            type: c.type,
                            id: b64urlDecode(c.id)
                        })),
                        extensions: {}
                    }
                };

                // Add PRF extension if requested
                if (opts.extensions?.prf?.eval) {
                    const prfInput = {
                        eval: {
                            first: b64urlDecode(opts.extensions.prf.eval.first)
                        }
                    };
                    if (opts.extensions.prf.eval.second) {
                        prfInput.eval.second = b64urlDecode(opts.extensions.prf.eval.second);
                    }
                    getOptions.publicKey.extensions.prf = prfInput;
                }

                // Get assertion
                const assertion = await navigator.credentials.get(getOptions);
                
                // Extract PRF results
                const extResults = assertion.getClientExtensionResults?.() || {};
                let prfFirst = '';
                let prfSecond = '';
                if (extResults.prf?.results) {
                    prfFirst = b64urlEncode(extResults.prf.results.first);
                    if (extResults.prf.results.second) {
                        prfSecond = b64urlEncode(extResults.prf.results.second);
                    }
                }

                // Send result back
                const result = {
                    state: state,
                    credentialId: b64urlEncode(assertion.rawId),
                    authenticatorData: b64urlEncode(assertion.response.authenticatorData),
                    signature: b64urlEncode(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? b64urlEncode(assertion.response.userHandle) : '',
                    clientDataJSON: b64urlEncode(assertion.response.clientDataJSON),
                    prfFirst: prfFirst,
                    prfSecond: prfSecond
                };

                const resp = await fetch(callbackUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(result)
                });

                statusEl.className = 'status success';
                statusEl.innerHTML = '<h2>✅ Authentication Successful!</h2><p>You can close this window.</p>';
            } catch (err) {
                console.error('Authentication failed:', err);
                
                await fetch(callbackUrl, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({state: state, error: err.message || err.toString()})
                });

                statusEl.className = 'status error';
                statusEl.innerHTML = '<h2>❌ Authentication Failed</h2><p>' + (err.message || err) + '</p>';
            }
        }

        authenticate();
    </script>
</body>
</html>`, optsJSON, state, port)
}
