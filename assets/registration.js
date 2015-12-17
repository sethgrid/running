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
    success: summaryData,
    fail: function(data){
        console.log('failed to get summary data: '+data);
    },
});

function summaryData(data){
    var summary = JSON.parse(data);
    console.log("summary:",summary)
    if (!summary.CrowdRiseUsername.length){
        var el = $('<div id="crowdrise_signup">You need to sign up for CrowdRise!</div>');
        $("#main_container").append(el);
    } else {
        var el = $('<div id="crowdrise_widget">You have a CrowdRise username, we should display a widget!</div>');
        $("#main_container").append(el);
    }
    USER_EMAIL = summary.email;
    checkCrowdriseForUser(tokenData, summary.email);
}

function checkCrowdriseForUser(tokenData,email){
    var jqxhr = $.ajax({
        url: "crowdrise/api/check_if_user_exists",
        method: 'POST',
        headers: {
            'Authorization':"Bearer "+tokenData.access_token,
        },
        data: {'email': email},
        success: CrowdRiseCheckUserResult,
        fail: function(data){
            console.log('failed to check for crowdrise user: '+data);
        },
    });
}

function CrowdRiseCheckUserResult(data){
    console.log('check user result:', data);
    obj = JSON.parse(data);
    console.log('user exists?',obj.result[0].user_exists);
}

function CrowdRiseCheckNewUserResult(data){
	console.log('create user result:', data);
}

function createCrowdriseUser(form){
	form.submit.disabled = true;
	form.submit.innerHTML = "<i class='fa fa-spinner fa-spin'> </i> Submitting..."
	var jqxhr = $.ajax({
        url: "crowdrise/api/signup",
        method: 'POST',
        headers: {
            'Authorization':"Bearer "+tokenData.access_token,
        },
        data: {'email': USER_EMAIL, 
        	   'first_name': form.firstname.value,
        	   'last_name': form.lastname.value,
        	   'password': form.password.value
        	},
        success: CrowdRiseCheckNewUserResult,
        fail: function(data){
            console.log('failed to check crowdrise healthcheck: '+data);
        },
    });
}