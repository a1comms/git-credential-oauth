export default {
    async fetch(request, env, ctx) {
        const { searchParams } = new URL(request.url);
        let code = searchParams.get('code');
        let state = searchParams.get('state');

        let authenticationToken;

        if (
            (typeof code === "string" && code.length > 0)
            &&
            (typeof state === "string" && state.length > 0)
        ) {
            authenticationToken = b64EncodeUnicode(
                JSON.stringify({
                    "code": code,
                    "state": state
                })
            );
        } else {
            return new Response("HTTP 400 Bad Request", {
                status: 400,
                statusText: "Bad Request"
            });
        }

        const html = `<!DOCTYPE html>
  <html lang="en">
  
  <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>BitBucket Authentication for Git</title>
  
      <link rel="stylesheet"
          href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,400i,700&display=fallback">
  
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
          integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
          crossorigin="anonymous" referrerpolicy="no-referrer" />
  
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/icheck-bootstrap/3.0.1/icheck-bootstrap.min.css"
          integrity="sha512-8vq2g5nHE062j3xor4XxPeZiPjmRDh6wlufQlfC6pdQ/9urJkU07NM0tEREeymP++NczacJ/Q59ul+/K2eYvcg=="
          crossorigin="anonymous" referrerpolicy="no-referrer" />
  
      <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/css/adminlte.css"
          integrity="sha512-0w74+CBOlTu44j+e8dSKFl/5Qg9JoJhfK7Gf/+5bdtzJgqP7N3+02W02rQqRrywlm8cKXg3YwQWMBIS18GYPZg=="
          crossorigin="anonymous" referrerpolicy="no-referrer" />
  </head>
  
  <body class="hold-transition login-page">
      <div class="login-box">
          <div class="card card-outline card-primary">
              <div class="card-header text-center">
                  <a href="../../index2.html" class="h1"><b>BitBucket</b> for <b>Git</b></a>
              </div>
              <div class="card-body">
                  <p class="login-box-msg">Copy your authentication token below and paste it onto your terminal to
                      complete your login.
                  </p>
                  <div class="input-group mb-3">
                      <input type="text" class="form-control" id="authentication-token" value="` + authenticationToken + `" onclick="copyvalue()"
                          placeholder="Authentication Token">
                      <div class="input-group-append">
                          <div class="input-group-text">
                              <span class="fa-regular fa-clone" id="copy-icon" onclick="copyvalue()"></span>
                          </div>
                      </div>
                  </div>
                  <div class="row">
                      <div class="col-12">
                          <button type="submit" id="copy-button" onclick="copyvalue()"
                              class="btn btn-primary btn-block">Copy Token</button>
                      </div>
  
                  </div>
              </div>
  
          </div>
      </div>
  
  
      <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.4/jquery.min.js"
          integrity="sha512-pumBsjNRGGqkPzKHndZMaAG+bir374sORyzM3uulLV14lN5LyykqNk8eEeUlUkB3U0M4FApyaHraT65ihJhDpQ=="
          crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  
      <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/4.6.1/js/bootstrap.bundle.min.js"
          integrity="sha512-mULnawDVcCnsk9a4aG1QLZZ6rcce/jSzEGqUkeOLy0b6q0+T6syHrxlsAGH7ZVoqC93Pd0lBqd6WguPWih7VHA=="
          crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  
      <script src="https://cdnjs.cloudflare.com/ajax/libs/admin-lte/3.2.0/js/adminlte.min.js"
          integrity="sha512-KBeR1NhClUySj9xBB0+KRqYLPkM6VvXiiWaSz/8LCQNdRpUm38SWUrj0ccNDNSkwCD9qPA4KobLliG26yPppJA=="
          crossorigin="anonymous" referrerpolicy="no-referrer"></script>
  
      <script>
          function copyvalue() {
              navigator.clipboard.writeText($('#authentication-token').val()).then(function () {
                  $('#copy-button').html('Copied!');
                  $('#copy-icon').addClass('fa-shake');
                  setTimeout(function () {
                      $('#copy-button').html('Copy Token');
                      $('#copy-icon').removeClass('fa-shake');
                  }, 500);
              }, function () {
                  console.log("clipboard copy failed");
              });
          }
      </script>
  </body>
  
  </html>`;

        return new Response(html, {
            headers: {
                "content-type": "text/html;charset=UTF-8",
            },
        });
    },
};

function b64EncodeUnicode(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
        return String.fromCharCode(parseInt(p1, 16))
    }))
}