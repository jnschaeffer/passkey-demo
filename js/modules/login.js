async function login() {
    const url = 'http://localhost/webauthn/login/begin';

    let beginResponse = await fetch(url);

    if (!beginResponse.ok) {
        throw new Error(`Response status: ${beginResponse.status}`);
    }

    const beginBody = await beginResponse.json();

    const options = PublicKeyCredential.parseRequestOptionsFromJSON(beginBody.publicKey);

    let credentialInfo = await window.navigator.credentials.get({publicKey: options});

    let finishResponse = await fetch(
        `http://localhost/webauthn/login/finish`,
        {
            method: "POST",
            body: JSON.stringify(credentialInfo.toJSON()),
        },
    );

    if (!finishResponse.ok) {
        throw new Error(`Response status: ${finishResponse.status}`);
    }

    const finishBody = await finishResponse.json();

    const username = finishBody.username;
    
    return `Hello, ${username}!`;
}

export default login;
