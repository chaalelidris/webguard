// all the functions related to webGuard update, including showing up modal, notification etc will be here

// Source : https://stackoverflow.com/a/32428268
function checkDailyUpdate() {
  if (!hasOneDayPassed()) return false;
  console.log("Checking Daily Update...");
  fetch("/api/webguard/update/")
    .then((response) => response.json())
    .then(function (response) {
      if (response["update_available"]) {
        window.localStorage.setItem("update_available", true);
        $(".webguard_update_available").show();
        update_available(response["latest_version"], response["changelog"]);
      } else {
        window.localStorage.setItem("update_available", false);
        $(".webguard_update_available").hide();
      }
    });
}

function check_webguard_update() {
  if (
    window.localStorage.getItem("update_available") &&
    window.localStorage.getItem("update_available") === "true"
  ) {
    // redirect to github release page
    window.open("https://github.com/yogeshojha/webguard/releases", "_blank");
  } else {
    Swal.fire({
      title: "Checking webGuard latest version...",
      allowOutsideClick: false,
    });
    swal.showLoading();
    fetch("/api/webguard/update/")
      .then((response) => response.json())
      .then(function (response) {
        console.log(response);
        swal.close();
        if (response["description"] == "RateLimited") {
          Swal.fire({
            title: "Oops!",
            text: "Github rate limit exceeded, please try again in an hour!",
            icon: "error",
          });
          window.localStorage.setItem("update_available", false);
          $(".webguard_update_available").hide();
        } else if (response["update_available"]) {
          window.localStorage.setItem("update_available", true);
          $(".webguard_update_available").show();
          update_available(response["latest_version"], response["changelog"]);
        } else {
          window.localStorage.setItem("update_available", false);
          $(".webguard_update_available").hide();
          Swal.fire({
            title: "Update not available",
            text: "You are running the latest version of webGuard!",
            icon: "info",
          });
        }
      });
  }
}

function update_available(latest_version_number, changelog) {
  // Ensure marked and highlight.js are loaded, to render the changelog
  Promise.all([
    loadScript("https://cdn.jsdelivr.net/npm/marked/marked.min.js"),
    loadScript(
      "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/highlight.min.js"
    ),
    loadCSS(
      "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.7.0/styles/github.min.css"
    ),
  ]).then(() => {
    marked.setOptions({
      highlight: function (code, lang) {
        const language = hljs.getLanguage(lang) ? lang : "plaintext";
        return hljs.highlight(code, { language }).value;
      },
      langPrefix: "hljs language-",
    });

    const parsedChangelog = marked.parse(changelog);

    const changelogStyle = `
        <style>
          .changelog-content {
            background-color: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            text-align: left;
          }
          .changelog-content h1, .changelog-content h2 {
            border-bottom: 1px solid #eaecef;
            padding-bottom: 0.3em;
          }
          .changelog-content pre {
            background-color: #f6f8fa;
            border-radius: 6px;
            padding: 16px;
          }
          .changelog-content code {
            background-color: rgba(27,31,35,.05);
            border-radius: 3px;
            font-size: 85%;
            margin: 0;
            padding: .2em .4em;
          }
        </style>
      `;

    Swal.fire({
      title: "Update Available!",
      html: `
          ${changelogStyle}
          <h5>webGuard's new update ${latest_version_number} is available, please follow the update instructions.</h5>
          <div class="changelog-content" style="max-height: 500px;" data-simplebar>
            ${parsedChangelog}
          </div>
        `,
      icon: "info",
      confirmButtonText: "Update Instructions",
      showCancelButton: true,
      cancelButtonText: "Dismiss",
      width: "70%",
      didOpen: () => {
        document.querySelectorAll("pre code").forEach((block) => {
          hljs.highlightBlock(block);
        });
      },
    }).then((result) => {
      if (result.isConfirmed) {
        window.open("https://www.webguard.wiki/update", "_blank");
      }
    });
  });
}

// Source: https://stackoverflow.com/a/32428268
function hasOneDayPassed() {
  var date = new Date().toLocaleDateString();
  if (window.localStorage.getItem("last_update_checked") == date) {
    return false;
  }
  window.localStorage.setItem("last_update_checked", date);
  return true;
}

function showAfterUpdatePopup() {
  // this function will show a popup after the update is done to tell user about the new features
  const currentVersion = document.body.getAttribute("data-webguard-version");
  const lastShownVersion = localStorage.getItem("lastShownUpdateVersion");

  
}

$(document).ready(function () {
    // show popup after update
    showAfterUpdatePopup();
  // hide badge if update does not exists
  if (
    window.localStorage.getItem("update_available") &&
    window.localStorage.getItem("update_available") === "true"
  ) {
    $(".webguard_update_available").show();
  } else {
    $(".webguard_update_available").hide();
  }
});
