function showControlsTable(scanResult){
	var vulns = scanResult;	
	table = jQuery('#vulnsTable').DataTable({
		"autoWidth": false, 
		"language": {
    		"emptyTable": "No vulnerabilities found"
		 },
		 "dom": '<"vulns-table-top"l<"custom-filters">>rt<"vulns-table-bottom"ip><"clear">',
        "aaData": vulns,
        "aoColumns":[         
            { "mData": "cid", sDefaultContent :  '-', "width": "5%"},
            { "mData": "statement", sDefaultContent :  '-', "width": "15%"},
            { "mData": "criticality", sDefaultContent :  '-', "width": "7%"},
            { "mData": "pName", sDefaultContent :  '-', "width": "9%"},
            { "mData": "status", sDefaultContent :  '-', "width": "8%"},
            { "mData": "unexpected_values", sDefaultContent :  '-', "width": "15%"},
            { "mData": "missing_values", sDefaultContent :  '-', "width": "15%"}
        ],
        'aoColumnDefs': [
        	{ "sTitle": "Control ID", "aTargets": [0], "width": "5%", "className": "center"},
            { "sTitle": "Title", "aTargets": [1], "width": "15%", "className": "left" },    
            { "sTitle": "Criticality", "aTargets": [2], "width": "7%", "className": "center"},
            { "sTitle": "Policy Title", "aTargets": [3], "width": "9%", "className": "left"},
            { "sTitle": "Status", "aTargets": [4], "width": "8%", "className": "center"},
            { "sTitle": "Unexpected Values", "aTargets": [5], "width": "15%", "className": "left"},
            { "sTitle": "Missing Values", "aTargets": [6], "width": "15%", "className": "left"}
        ]
    });
	
	 jQuery('#vulnsTable tbody').on('click', 'td.details-control', function () {
	        var tr = jQuery(this).closest('tr');
	        var row = table.row( tr );
	 
	        if ( row.child.isShown() ) {
	            // This row is already open - close it
	            row.child.hide();
	            tr.removeClass('shown');
	        }
	        else {
	            // Open this row
	            row.child( format(row.data()) ).show();
	            tr.addClass('shown');
	        }
	    });
	    
	    jQuery("#vulnsTable tbody").on("click", ".more-cve-records", function(e){
	    	var tr = jQuery(this).closest('tr');
	    	var row = table.row( tr );
	    	row.child( format(row.data()) ).show();
	        tr.addClass('shown');
	        return false;
	    });
	    
	    
	    jQuery(".softwares-custom-filters").html(
	    	'<div class="sev-filter-div">' + 
	    	'<span class="filters-label">Show Only: </span>' + '</div>'+ 
	    	'<ul class="filters-list">' +
	    	'<li><input class="custom-filter-checkbox" type="checkbox" id="sw-patchable" value="sw-patchable">  <label for="sw-patchable" class="checkbox-title"> Patchable  </li>' +
	    	'</ul>' 
	    );
	    jQuery(".custom-filters").html(
	    	'<div class="sev-filter-div">' + 
	    	'<span class="filters-label">Show Only: </span>' + 
	    	'<span class="sev-filter-label" >Criticality </span>' + 
	    	'<select class="criticality-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="URGENT"> URGENT </option>' +
	    	'<option value="SERIOUS"> SERIOUS </option>' +
	    	'<option value="CRITICAL"> CRITICAL </option>' +
	    	'<option value="MEDIUM"> MEDIUM </option>' +
	    	'<option value="MINIMAL"> MINIMAL </option>' +
	    	'</select>' +
	    	'<span class="sev-filter-label" >Status </span>' +
	    	'<select class="status-dropdown">' + 
	    	'<option value="">All</option>' +
	    	'<option value="Passed"> Passed </option>' +
	    	'<option value="Failed"> Failed </option>' +
	    	'<option value="Error"> Error </option>' +
	    	'<option value="Exceptions"> Exceptions </option>' +
	    	'</select>' +
	    	'<button class="reset-filters" onclick="clearFilter()">Reset Filters</button>' +
	    	'</div>'
	    );
	    
	    jQuery(".custom-filters-left").html(
	    	
	    );
	    
	    jQuery('.criticality-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(2).search( valueSelected ).draw();
	    });
	    
	    jQuery('.status-dropdown').on('change', function(e){
	    	 var optionSelected = jQuery("option:selected", this);
			 var valueSelected = this.value;
			 table.columns(4).search( valueSelected ).draw();
	    });  
	    
}

function setFailAndErrorControlSeverityWise(policy) {
    var controlSeverityWise = [0,0,0,0,0, 0,0,0,0,0, 0,0,0,0,0];
    if (policy == "ALL") {
        for (var key in scanResults) {
            var values = scanResults[key];
            for (var controlsKey in values["controls"]) {
                var controlsValue = values["controls"][controlsKey];
                if (controlsValue["status"] == "Error") {
                    if (controlsValue["criticality"] == "MINIMAL") {
                    controlSeverityWise[0] = controlSeverityWise[0] + 1;
                    }
                    if (controlsValue["criticality"] == "MEDIUM") {
                        controlSeverityWise[1] = controlSeverityWise[1] + 1;
                    }
                    if (controlsValue["criticality"] == "CRITICAL") {
                        controlSeverityWise[2] = controlSeverityWise[2] + 1;
                    }
                    if (controlsValue["criticality"] == "SERIOUS") {
                        controlSeverityWise[3] = controlSeverityWise[3] + 1;
                    }
                    if (controlsValue["criticality"] == "URGENT") {
                        controlSeverityWise[4] = controlSeverityWise[4] + 1;
                    }
                }
                else if (controlsValue["status"] == "Failed") {
                    if (controlsValue["criticality"] == "MINIMAL") {
                    controlSeverityWise[5] = controlSeverityWise[5] + 1;
                    }
                    if (controlsValue["criticality"] == "MEDIUM") {
                        controlSeverityWise[6] = controlSeverityWise[6] + 1;
                    }
                    if (controlsValue["criticality"] == "CRITICAL") {
                        controlSeverityWise[7] = controlSeverityWise[7] + 1;
                    }
                    if (controlsValue["criticality"] == "SERIOUS") {
                        controlSeverityWise[8] = controlSeverityWise[8] + 1;
                    }
                    if (controlsValue["criticality"] == "URGENT") {
                        controlSeverityWise[9] = controlSeverityWise[9] + 1;
                    }
                }
                else if (controlsValue["status"] == "Exceptions") {
                    if (controlsValue["criticality"] == "MINIMAL") {
                    controlSeverityWise[10] = controlSeverityWise[10] + 1;
                    }
                    if (controlsValue["criticality"] == "MEDIUM") {
                        controlSeverityWise[11] = controlSeverityWise[11] + 1;
                    }
                    if (controlsValue["criticality"] == "CRITICAL") {
                        controlSeverityWise[12] = controlSeverityWise[12] + 1;
                    }
                    if (controlsValue["criticality"] == "SERIOUS") {
                        controlSeverityWise[13] = controlSeverityWise[13] + 1;
                    }
                    if (controlsValue["criticality"] == "URGENT") {
                        controlSeverityWise[14] = controlSeverityWise[14] + 1;
                    }
                }

            }
        }
    }
    else {
        var values = scanResults[policy];
        for (var controlsKey in values["controls"]) {
            var controlsValue = values["controls"][controlsKey];
            if (controlsValue["status"] == "Error") {
                if (controlsValue["criticality"] == "MINIMAL") {
                controlSeverityWise[0] = controlSeverityWise[0] + 1;
                }
                if (controlsValue["criticality"] == "MEDIUM") {
                    controlSeverityWise[1] = controlSeverityWise[1] + 1;
                }
                if (controlsValue["criticality"] == "CRITICAL") {
                    controlSeverityWise[2] = controlSeverityWise[2] + 1;
                }
                if (controlsValue["criticality"] == "SERIOUS") {
                    controlSeverityWise[3] = controlSeverityWise[3] + 1;
                }
                if (controlsValue["criticality"] == "URGENT") {
                    controlSeverityWise[4] = controlSeverityWise[4] + 1;
                }
            }
            else if (controlsValue["status"] == "Failed") {
                if (controlsValue["criticality"] == "MINIMAL") {
                controlSeverityWise[5] = controlSeverityWise[5] + 1;
                }
                if (controlsValue["criticality"] == "MEDIUM") {
                    controlSeverityWise[6] = controlSeverityWise[6] + 1;
                }
                if (controlsValue["criticality"] == "CRITICAL") {
                    controlSeverityWise[7] = controlSeverityWise[7] + 1;
                }
                if (controlsValue["criticality"] == "SERIOUS") {
                    controlSeverityWise[8] = controlSeverityWise[8] + 1;
                }
                if (controlsValue["criticality"] == "URGENT") {
                    controlSeverityWise[9] = controlSeverityWise[9] + 1;
                }
            }
            else if (controlsValue["status"] == "Exceptions") {
                if (controlsValue["criticality"] == "MINIMAL") {
                controlSeverityWise[10] = controlSeverityWise[10] + 1;
                }
                if (controlsValue["criticality"] == "MEDIUM") {
                    controlSeverityWise[11] = controlSeverityWise[11] + 1;
                }
                if (controlsValue["criticality"] == "CRITICAL") {
                    controlSeverityWise[12] = controlSeverityWise[12] + 1;
                }
                if (controlsValue["criticality"] == "SERIOUS") {
                    controlSeverityWise[13] = controlSeverityWise[13] + 1;
                }
                if (controlsValue["criticality"] == "URGENT") {
                    controlSeverityWise[14] = controlSeverityWise[14] + 1;
                }
            }
        }
    }
    return controlSeverityWise;
}

function resetCanvas() {
    if (allControlsChart != null) {
        document.getElementById("allControls-parent").innerHTML = '<canvas id="allControls" height="160px"></canvas>';
        allControlsChart.destroy();
    }
}	


function drowAllControlsChart(failControls, errorControls, passControls, exceptionsControls) {
	var c = jQuery("#allControls").get(0);
	var ctx = c.getContext("2d");
	var totalControls = parseInt(passControls) + parseInt(exceptionsControls) + parseInt(failControls) + parseInt(errorControls);
	var count = [passControls, failControls, errorControls, exceptionsControls];
	var labels = [passControls.toString(), failControls.toString(), errorControls.toString(), exceptionsControls.toString()]
	var colors = ["#54a92a", "#de1d0b", "#b0bfc6", "#ab23a6"];
	
	if (totalControls == 0) {
        count = ["1", "1", "1", "1"];
        labels = ["0", "0", "0", "0", "0"];
        colors = ["#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6", "#B0BFc6"];
      }
	
	var options = {
	responsive: true,
	maintainAspectRatio: false,
	plugins: {
		"title": {
	          display: true,
	          text: 'Total Controls (' + totalControls.toString() + ')'
        	},
		"legend": {
		      display: true,
		      position: "right"
		    },
	    "tooltip": {
	      "enabled": true,
	      "callbacks": 
	      	{
                label: function(context) 
                {
                    var label = context.label;
                    return label;
             	}     
              }
	    	}
    	}
	};
	var pieData = {
	    "datasets": [{
	      "data": count,
	      "backgroundColor": colors
	    }],
	
	    // These labels appear in the legend and in the tooltips when hovering different arcs
	    "labels": [
	    	"Passed: "+ labels[0],
	      	"Failed: "+ labels[1],
	      	"Error: "+ labels[2],
          	"Exceptions: "+ labels[3]
	    ]
	  };
	  allControlsChart = new Chart(ctx, { "type": "pie", "data": pieData, "options": options });
	 
}
	
function drawResultSummaryTable(ControlsFailError) {
    for (i = 4; i >= 0; i--) {
        var ind = i + (5 - i) + (4 - i);
        var indExceptions = i + (10 - i) + (4 - i);
        document.getElementById("build-summary-table").rows[1].cells[1+i].innerHTML = ControlsFailError[ind].toString();
        document.getElementById("build-summary-table").rows[2].cells[1+i].innerHTML = ControlsFailError[4 - i].toString();
        document.getElementById("build-summary-table").rows[3].cells[1+i].innerHTML = ControlsFailError[indExceptions].toString();
    }

}

function removeUnwantedChar(scanResultsRaw) {
	var strData = JSON.stringify(scanResultsRaw).replace(/\&amp;/g,'&')
	var objData = JSON.parse(strData);
	if (typeof objData != "object") {
		objData = JSON.parse(objData);
	}
	return objData;
}
	