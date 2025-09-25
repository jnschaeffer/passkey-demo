import registerCredential from "./modules/register.js";
import login from "./modules/login.js";

function initialize() {
    const usernameField = document.querySelector("#username-field");

    const registerButton = document.querySelector("#btn-register");

    const loginButton = document.querySelector("#btn-login");

    const output = document.querySelector("#output");

    registerButton.addEventListener("click", async () => {        
        let username = usernameField.value;
        
        let result = await registerCredential(username);

        output.textContent = result;
    });

    loginButton.addEventListener("click", async () => {        
        let result = await login()

        output.textContent = result;
    });
}

addEventListener("load", (event) => {
    initialize();
});
