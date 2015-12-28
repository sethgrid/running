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
    window.location.assign("http://300daysofrun.com/setup");
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