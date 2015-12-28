$(document).ready(function(){
    $('#charityname').keypress(function(e){
      if(e.keyCode==13) {
      	$('#search').click();
  	  	return false;
      }
    });
});

$(document).ready(function() {
    $('#search').click(function() {
      searchCrowdriseCharity($('#charityname').val());
      return false;
    });
});

function searchCrowdriseCharity(keywords, page){
	if (typeof(page)==='undefined') page = 1;
	CURRENT_PAGE = page;
	console.log("Keywords: " + keywords);
	$("#search").html("<i class='fa fa-spinner fa-spin'> </i> Searching...");
	$("#charity-search-results").empty();
	$("#search-pagination").empty();
	var jqxhr = $.ajax({
        url: "crowdrise/api/charity_basic_search",
        method: 'GET',
        headers: {
            'Authorization':"Bearer "+tokenData.access_token,
        },
        data: {'keywords': keywords, 
        	   'page': page,
        	},
        success: crowdriseSearchResult,
        fail: function(data){
            console.log('failed to search crowdrise charities: '+data);
        },
    });
}

function crowdriseSearchResult(data){
	$("#search").html("Search");
	var results = JSON.parse(data);
	console.log(results);

	$.each(results["result"][0], function(key,value) {
	  if(value.hasOwnProperty('guidestar')) {
	  	console.log(value.guidestar.charityName);
	  	$("#charity-search-results").append("<div class='panel panel-default' id='" + value.guidestar.ein + "'>");
	  	$("#" + value.guidestar.ein).append('<div class="panel-heading"><strong>' + value.guidestar.charityName + '</strong>  - ' + value.guidestar.city + ", " + value.guidestar.state + '</div>');
	  	$("#" + value.guidestar.ein).append('<div class="panel-body">' + value.guidestar.mission + '</div');
	  	$("#" + value.guidestar.ein).append('<div class="panel-footer"><a href="#" class="btn btn-sm btn-success" onClick="createCrowdriseTeam(&apos;' + value.guidestar.ein + '&apos;); return false;">Select ' +  value.guidestar.charityName + '</a></div>');
	  	$("#charity-search-results").append("</div>");
	  }
	});
	var pages = Math.ceil(parseInt(results["result"][0].totalResults)/10);
	$("#search-pagination").append("<nav><ul id='pagination' class='pagination'>");
	for ( var i = 0; i < pages; i++ ) {
		var pageClass = "";
		if (CURRENT_PAGE == i+1) pageClass = " class='active'";
	    $("#pagination").append('<li' + pageClass + '><a href="#" onClick="searchCrowdriseCharity(&apos;' + $('#charityname').val() + '&apos;, ' + (i+1).toString() + ')">' + (i+1).toString() + '</a></li>');
	}
	$("#search-pagination").append("</nav></ul>");
}

function createCrowdriseTeam(ein){
	$("#charity-search-results").empty().append('<h3><i class="fa fa-spinner fa-spin"> </i> Communicating with Crowdrise...</h3>');
	$("#search-pagination").empty();
	var jqxhr = $.ajax({
        url: "crowdrise/api/create_event_team?ein=" + ein,
        method: 'GET',
        headers: {
            'Authorization':"Bearer "+tokenData.access_token,
        },
        success: CrowdRiseTeamResult,
        fail: function(data){
            console.log('failed to create team: '+data);
        },
    });
}

function CrowdRiseTeamResult(data){
    console.log('team creation result:', data);
    //Parse JSON, display errors or redirect on success
    var results = JSON.parse(data);
    if (results["result"][0].team_created){
    	window.location.href = "http://300daysofrun.com/app?new_user=true";
    } else {
    	$("#charity-search-results").empty().append("Sorry, something went wrong when trying to set up your Crowdrise Fundraiser. Please contact help@300daysofrun.com and we'll get it sorted out.");
		$("#search-pagination").empty();
    }

}