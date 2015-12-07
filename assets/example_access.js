// grab the token data that is present on all authenticated pages
var AUTH_COOKIE = "auth_cookie";
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

    pingCrowdRise(tokenData);
}

function pingCrowdRise(tokenData){
    var jqxhr = $.ajax({
        url: "crowdrise/api/heartbeat",
        method: 'GET',
        headers: {
            'Authorization':"Bearer "+tokenData.access_token,
        },
        success: CrowdRisePingResult,
        fail: function(data){
            console.log('failed to check crowdrise healthcheck: '+data);
        },
    });
}

function CrowdRisePingResult(data){
    console.log('ping result:', data);
}