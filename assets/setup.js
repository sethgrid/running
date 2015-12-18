// grab the token data that is present on all authenticated pages
var AUTH_COOKIE = "auth_cookie";
var USER_EMAIL = "";
var tokenData = JSON.parse(atob($.cookie(AUTH_COOKIE)).split("::hmac::")[0]);
console.log("tokenData:",tokenData)
//pingCrowdRise(tokenData);

function searchCrowdriseCharity(form){
	console.log("Keywords: " + form.charityname.value);
	//return;
	var jqxhr = $.ajax({
        url: "crowdrise/api/charity_basic_search",
        method: 'GET',
        headers: {
            'Authorization':"Bearer "+tokenData.access_token,
        },
        data: {'keywords': form.charityname.value, 
        	},
        success: crowdriseSearchResult,
        fail: function(data){
            console.log('failed to search crowdrise charities: '+data);
        },
    });
}

function crowdriseSearchResult(data){
	console.log('charity search result:', data);
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