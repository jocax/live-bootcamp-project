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
    console.log('Logout URL:', url);

    fetch(url, {
        method: 'POST',
        credentials: 'include', // This will include cookies in the request
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
    })
        .then(response => {
            console.log('Logout response status:', response.status);
            console.log('Logout response headers:', response.headers);

            // Log the response body
            return response.text().then(text => {
                console.log('Logout response body:', text);

                if (response.ok) {
                    loginLink.style.display = "block";
                    logoutLink.style.display = "none";
                    protectImg.src = buildUrl("assets/default.jpg");
                } else {
                    alert("Failed to logout");
                }
            });
        })
        .catch(error => {
            console.error('Logout error:', error);
        });
});

(() => {
    const protectedUrl = buildUrl('protected');
    console.log('Fetching protected URL:', protectedUrl);

    fetch(protectedUrl)
        .then(response => {
            console.log('Protected response status:', response.status);
            console.log('Protected response ok:', response.ok);
            console.log('Protected response headers:', response.headers);

            // Clone the response so we can read it twice if needed
            const clonedResponse = response.clone();

            // Always try to read the response body for debugging
            return clonedResponse.text().then(text => {
                console.log('Protected response body:', text);

                if (response.ok) {
                    loginLink.style.display = "none";
                    logoutLink.style.display = "block";

                    // Try to parse as JSON
                    try {
                        const data = JSON.parse(text);
                        console.log('Parsed JSON data:', data);

                        let img_url = data.img_url;
                        if (img_url !== undefined && img_url !== null && img_url !== "") {
                            console.log('Setting image URL:', img_url);
                            protectImg.src = img_url;
                        } else {
                            console.log('No img_url found, using default');
                            protectImg.src = buildUrl("assets/default.jpg");
                        }
                    } catch (e) {
                        console.error('JSON parse error:', e);
                        protectImg.src = buildUrl("assets/default.jpg");
                    }
                } else {
                    console.log('Response not ok, showing login');
                    loginLink.style.display = "block";
                    logoutLink.style.display = "none";
                    protectImg.src = buildUrl("assets/default.jpg");
                }
            });
        })
        .catch(error => {
            console.error('Protected fetch error:', error);
            loginLink.style.display = "block";
            logoutLink.style.display = "none";
            protectImg.src = buildUrl("assets/default.jpg");
        });
})();
