async function registerCredential(username) {
    const url = `http://localhost:8080/webauthn/${username}/register/start`;

    let beginResponse = await fetch(url);

    if (!beginResponse.ok) {
        throw new Error(`Response status: ${beginResponse.status}`);
    }

    const beginBody = await beginResponse.json();

    const options = PublicKeyCredential.parseCreationOptionsFromJSON(beginBody.publicKey);
    
    let credentialInfo = await window.navigator.credentials.create({publicKey: options});

    let finishResponse = await fetch(
        `http://localhost:8080/webauthn/${username}/register/finish`,
        {
            method: "POST",
            body: JSON.stringify(credentialInfo.toJSON()),
        },
    );

    if (!finishResponse.ok) {
        throw new Error(`Response status: ${finishResponse.status}`);
    }
    
    return `Successfully registered authenticator for ${username}!`;
}

export default registerCredential;
