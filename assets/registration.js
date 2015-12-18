// grab the token data that is present on all authenticated pages
var AUTH_COOKIE = "auth_cookie";
var USER_EMAIL = "";
var tokenData = JSON.parse(atob($.cookie(AUTH_COOKIE)).split("::hmac::")[0]);
console.log("tokenData:",tokenData)

// call the backend to get user data
var result = $.ajax({
    url: "user/"+tokenData.athlete.id+"/summary",
    headers: {
        'Authorization':"Bearer "+tokenData.access_token,
    },
    method: 'GET',
    fail: function(data){
        console.log('failed to get summary data: '+data);
    },
});

function CrowdRiseCreateNewUserResult(data){
	console.log('create user result:', data);
    $("#result").replaceWith("<h4>Crowdrise signup complete. After this, the user will be taken to a page to set up their team. That part's not done yet, so just <a href='/'>Click here</a> to go back to the homepage for now.</h4>");
}

function crowdriseSetup(form){
	form.submit.disabled = true;
    form.submit.innerHTML = "<i class='fa fa-spinner fa-spin'> </i> Communicating with Crowdrise...";
    var jqxhr = $.ajax({
        url: "crowdrise/api/signup",
        method: 'POST',
        headers: {
            'Authorization':"Bearer "+tokenData.access_token,
        },
        success: CrowdRiseCreateNewUserResult,
        fail: function(data){
            console.log('failed to create crowdrise user: '+data);
        },
    });
}