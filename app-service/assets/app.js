// Get the base path from document.baseURI
const baseUrl = new URL(document.baseURI);
const contextPath = baseUrl.pathname.endsWith('/') ? baseUrl.pathname : baseUrl.pathname + '/';

const loginLink = document.getElementById("login-link");
const logoutLink = document.getElementById("logout-link");
const protectImg = document.getElementById("protected-img");

// Helper function to build URLs with context path
function buildUrl(path) {
    // Remove leading slash from path if present
    const cleanPath = path.startsWith('/') ? path.substring(1) : path;
    return contextPath + cleanPath;
}

logoutLink.addEventListener("click", (e) => {
    e.preventDefault();

    let url = logoutLink.href;

    fetch(url, {
        method: 'POST',
        credentials: 'include', // This will include cookies in the request
    }).then(response => {
        if (response.ok) {
            loginLink.style.display = "block";
            logoutLink.style.display = "none";
            protectImg.src = buildUrl("assets/default.jpg");
        } else {
            alert("Failed to logout");
        }
    });
});

(() => {
    fetch(buildUrl('protected')).then(response => {
        if (response.ok) {
            loginLink.style.display = "none";
            logoutLink.style.display = "block";

            response.json().then(data => {
                let img_url = data.img_url;
                if (img_url !== undefined && img_url !== null && img_url !== "") {
                    protectImg.src = img_url;
                } else {
                    protectImg.src = buildUrl("assets/default.jpg");
                }
            });
        } else {
            loginLink.style.display = "block";
            logoutLink.style.display = "none";
            protectImg.src = buildUrl("assets/default.jpg");
        }
    });
})();
