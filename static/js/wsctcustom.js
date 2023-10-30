// SIMPLE SPINNER LOADING
function loading(){
  $("#loading").show();
  var spinner = "spinner";
}
// AD/SMB DATASET (ADD/RM Hosts IP)
$(document).ready(function(){
    var count_hostsallow = 0;
    $("#add_hostsallow").on("click", function(){
        count_hostsallow += 1;            
        $("<input>").attr({ type: "text", class: "form-control", placeholder: "x.x.x.x", id: "hostsallow_"+count_hostsallow, name: "hostsallow"}).appendTo("#item_hostsallow").wrap(("</input>"));
    });
    $("#remove_hostsallow").on("click", function(){              
        $("#hostsallow_"+count_hostsallow).remove();
        count_hostsallow -= 1;  
        if (count_hostsallow === -1) { count_hostsallow == 1; $("#hostsallow_"+count_hostsallow).remove();};        
    });     
})
$(document).ready(function(){
    var count_hostsdeny = 0;
    $("#add_hostsdeny").on("click", function(){
        count_hostsdeny += 1;            
        $("<input>").attr({ type: "text", class: "form-control", placeholder: "x.x.x.x", id: "hostsdeny_"+count_hostsdeny, name: "hostsdeny"}).appendTo("#item_hostsdeny").wrap(("</input>"));       
    });
    $("#remove_hostsdeny").on("click", function(){              
        $("#hostsdeny_"+count_hostsdeny).remove();
        count_hostsdeny -= 1;  
        if (count_hostsdeny === -1) { count_hostsdeny == 1; $("#hostsdeny_"+count_hostsdeny).remove();};        
    });    
})   
// AD/SMB USER MODIFY OPTIONS
function loading_modifyaduser(){
    $("#loading_modifyadgroup").hide();
    $("#loading_rmadusergroup").hide();            
    var ADUSER = $('#adlistusers :selected').text();             
    // CLEANING PREVIOUS INFO
    $('#username').val('');  
    $('#firstname').val('');  
    $('#lastname').val('');  
    $('#email').val('');  
    $('#whenCreated').val('');  
    $('#whenChanged').val('');  
    $('#userAccountControl').val('');      
    $('#admodifyuser').val('');      
    // Getting the user informations
    var xmlhttp = new XMLHttpRequest();
    var url = "/addmodify?adloadusermod="+ADUSER;    
    xmlhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        var myArr = (this.responseText);
        // Array to dictionary conversion
        var objectResponse = JSON.parse(myArr);        
        // Get values and fill them to the form
        var username = objectResponse.cn;
        var firstname = objectResponse.givenName;
        var lastname = objectResponse.sn;
        var email = objectResponse.userPrincipalName;
        var whenCreated = objectResponse.whenCreated;
        var whenChanged = objectResponse.whenChanged;
        var userAccountControl = objectResponse.userAccountControl;
        // var group = objectResponse.objectClass;
        if (userAccountControl == 514){
            userAccountControl = "DISABLED"
        }
        if (userAccountControl == 512){
            userAccountControl = "ENABLED"
        }
        if (userAccountControl == 544){
            userAccountControl = "ENABLED MUST CHANGE PASSWORD"
        }   
        if (userAccountControl == 66048){
            userAccountControl = "ENABLED PASSWORD DOESN'T EXPIRE"
        }                
        // Filling the info into the form
        $('#username').val(username);  
        $('#firstname').val(firstname);  
        $('#lastname').val(lastname);  
        $('#email').val(email);  
        $('#whenCreated').val(whenCreated);  
        $('#whenChanged').val(whenChanged);  
        $('#userAccountControl').val(userAccountControl); 
        $('#admodifyuser').val(username);            
        }
    };
    xmlhttp.open("GET", url, true);
    xmlhttp.send();
    // Show the form
    $("#loading_modifyaduser").show();    
}
// LIST GROUP MODIFY
function loading_modifyadgroup(){
    $("#loading_rmadusergroup").hide();
    $("#loading_modifyaduser").hide();
    var ADGROUP = $('#adlistgroups :selected').text(); 
    $('#adgroupname').val(ADGROUP);  
    $("#loading_modifyadgroup").show();
}
// AD/SMB REMOVE USER FROM GROUP
function loading_rmadusergroup(){    
    $("#loading_modifyaduser").hide();
    $("#loading_modifyadgroup").hide();
    $("#adlistusersgroup").hide();
    $("#ad_usersgroup").empty();
    var ADGROUP = $('#adlistgroups :selected').text();        
    // Getting the group informations
    var xmlhttp = new XMLHttpRequest();
    var url = "/addmodify?adloadusergroup="+ADGROUP;
    xmlhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        var myArr = (this.responseText);        
        // Array to dictionary conversion
        var objectResponse = JSON.parse(myArr);           
        for (i = objectResponse.length - 1; i >= 0; i--){
            var x = document.getElementById("ad_usersgroup");
            var option = document.createElement("option");
            option.text = objectResponse[i];
            x.add(option,x[i]);
        }        
    }};
    xmlhttp.open("GET", url, true);
    xmlhttp.send();              
    $("#loading_rmadusergroup").show();
}
// Remove user from group
function rmadusergroup(){   
    var ADGROUP = $('#adlistgroups :selected').text(); 
    var ADUSER = $('#ad_usersgroup :selected').text();    
    $('#outputadermusergroup').val(ADUSER);  
    $('#outputadermgroup').val(ADGROUP);  
    document.querySelector('.outputadermusergroup').textContent = ADUSER;    
    document.querySelector('.outputadermgroup').textContent = ADGROUP;    
}
function rmadusergroupmodal(){   
    var ADGROUP = $('#adlistgroups :selected').text(); 
    var ADUSER = $('#ad_usersgroup :selected').text();    
    document.querySelector('.outputadermusergroup').textContent = ADUSER;    
    $('#outputadermusergroup').val(ADUSER);  
    $('#outputadermgroup').val(ADGROUP);    
    document.querySelector('.outputadermgroup').textContent = ADGROUP;    
    // Getting the group informations
    var xmlhttp = new XMLHttpRequest();
    var url = "/addmodify?outputadermgroup="+ADGROUP+'&outputadermusergroup='+ADUSER;
    xmlhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        var myArr = (this.responseText);        
    }};
    xmlhttp.open("POST", url, true);
    xmlhttp.send();        
}
// RENAME GROUP MODAL
function renameadusergroup(){   
    var ADGROUPNEW = document.getElementById("adgroupname").value;     
    var ADGROUPOLD = $('#adlistgroups :selected').text();  
    $('#outputrenamegroupold').val(ADGROUPOLD);      
    $('#outputrenamegroup').val(ADGROUPNEW);         
    document.querySelector('.outputrenamegroupold').textContent = ADGROUPOLD;    
    document.querySelector('.outputrenamegroup').textContent = ADGROUPNEW;    
}
// RENAME GROUP PERMANENTLY
function renameadusergroupmodal(){   
    var ADGROUPNEW = document.getElementById("adgroupname").value;     
    var ADGROUPOLD = $('#adlistgroups :selected').text();  
    $('#outputrenamegroupold').val(ADGROUPOLD);  
    document.querySelector('.outputrenamegroupold').textContent = ADGROUPOLD;
    $('#outputrenamegroup').val(ADGROUPNEW);     
    document.querySelector('.outputrenamegroup').textContent = ADGROUPNEW;
    // Getting the group informations
    var xmlhttp = new XMLHttpRequest();
    var url = "/addmodify?outputrenamegroupold="+ADGROUPOLD+'&outputrenamegroup='+ADGROUPNEW;
    xmlhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        var myArr = (this.responseText);        
    }};
    xmlhttp.open("POST", url, true);
    xmlhttp.send();        
}
// ASSIGN USERNAME TO THE HIDDEN INPUT VALUE
function getaduserslist(){
    $("#loading_rmadusergroup").hide();
    $("#loading_modifyaduser").hide();
    $("#loading_modifyadgroup").hide();    
    var ADUSER = $('#adlistusers :selected').text();    
    $('#outputadenableuser').val(ADUSER);       
    $('#outputadedisableuser').val(ADUSER);       
    $('#outputadchangeuserpwd').val(ADUSER); 
    $('#outputadedeleteuser').val(ADUSER); 
    document.querySelector('.outputadenableuser').textContent = ADUSER;    
    document.querySelector('.outputadedisableuser').textContent = ADUSER;    
    document.querySelector('.outputadchangeuserpwd').textContent = ADUSER;    
    document.querySelector('.outputadedeleteuser').textContent = ADUSER;     
}
// USERNAME SELECTION FUNCTION
function aduserselected(){
    var ADUSER = $('#adlistusers :selected').text();    
    $('#outputadenableuser').val(ADUSER);    
    $('#outputadedisableuser').val(ADUSER);    
    $('#outputadedeleteuser').val(ADUSER);    
    $('#username').val(ADUSER);       
}
// MODAL DELETE GROUP PERMANTELY
function addeletegroupmodal(){ 
    var ADGROUP = $('#adlistgroups :selected').text(); 
    $('#outputaddeletegroup').val(ADGROUP);       
    document.querySelector('.outputaddeletegroup').textContent = ADGROUP;  
}
// ADD USER TO GROUP 
function adaddusergroupmodal(){ 
    var ADGROUP = $('#adlistgroups :selected').text(); 
    var ADUSER = $('#adlistusers :selected').text(); 
    $('#outputadaddusergroup').val(ADGROUP);       
    document.querySelector('.outputadaddusergroup').textContent = ADGROUP;  
    $('#outputadadduserg').val(ADUSER);       
    document.querySelector('.outputadadduserg').textContent = ADUSER;  
}
function adaddusergroup(){ 
    var ADGROUP = $('#adlistgroups :selected').text(); 
    var ADUSER = $('#adlistusers :selected').text(); 
    var xmlhttp = new XMLHttpRequest();
    var url = "/addmodify?adaddusergroup="+ADGROUP+"?adadduserg="+ADUSER;
    xmlhttp.open("POST", url, true);
    xmlhttp.send(); 
}

// DELETE GROUP PERMANTELY
function addeletegroup(){    
    var ADGROUP = $('#adlistgroups :selected').text();              
    var xmlhttp = new XMLHttpRequest();
    var url = "/addmodify?addeletegroup="+ADGROUP;
    xmlhttp.open("POST", url, true);
    xmlhttp.send(); 
}
// NEW iSCSI TARGET  
$(document).ready(function(){    
    var count_item = 0;
    $( "#add_target" ).on("click", function() {
        count_item += 1; 
        $("#target option").val("NEW").change();
        $("#target").hide();         
        $("#add_liqn_initiator").show();
        $("#add_cliqn_initiator").show();
        $("#add_ciqn_initiator").show();
        $("<input>").attr({ type: "text", required: "", class: "form-control", placeholder: "(iqn.1994-09.org.freebsd:freenas.local)", id: "niscsi_initiator_"+count_item, name: "niscsi_initiator"}).appendTo("#item_iqn_initiator").wrap(("</input>"));
      });
})
// NEW iSCSI INITIATOR IQN
$(document).ready(function(){    
    var count_item_iscsi_init = 0;
// ADD BUTTON
    $( "#add_iqn_initiator" ).on("click", function() {
            count_item_iscsi_init += 1; 
            // $("#iscsi_initiator option").val("NEW").change();
            $("#iscsi_initiator").hide();                
            $("#add_liqn_initiator").show();
            $("#add_cliqn_initiator").show();
            $("#add_ciqn_initiator").show();
            $("<input>").attr({ type: "text", required: "", class: "form-control", placeholder: "(iqn.1994-09.org.freebsd:freenas.local)", id: "niscsi_initiator_"+count_item_iscsi_init, name: "niscsi_initiator"}).appendTo("#item_iqn_initiator").wrap(("</input>"));     
      });
// REMOVE BUTTON
    $("#rem_iqn_initiator").on("click", function(){              
        $("#niscsi_initiator_"+count_item_iscsi_init).remove();
        count_item_iscsi_init -= 1;  
        if (count_item_iscsi_init === 0) {            
            $("#iscsi_initiator").show(); 
            $("#add_liqn_initiator").hide();
            $("#add_cliqn_initiator").hide();
            $("#add_ciqn_initiator").hide();            
            $("#niscsi_initiator_"+count_item_iscsi_init).remove();};
    });          
// CHANGES SELECTED
    $( "#iscsi_initiator" ).on("change", function handleChange(event) { 
            var value = (event.target.value); // get selected VALUE)                    
            if(value==='Select it from the list or press + for a new one'){
                $("#add_iqn_initiator").show();
                $("#rem_iqn_initiator").show();                
                // count_item_iscsi_init += 1;
            }else{
                $("#add_iqn_initiator").hide();
                $("#rem_iqn_initiator").hide();
                // count_item_iscsi_init += 1;
            }           
      } );
})
// iSCSI INITITATOR Filtered-IP
$(document).ready(function(){
    var count_auth_networks= 0;
    $("#add_auth_networks").on("click", function(){
        count_auth_networks += 1;            
        $("<input>").attr({ type: "text", class: "form-control", placeholder: "x.x.x.x", id: "auth_networks_"+count_auth_networks, name: "auth_networks"}).appendTo("#item_auth_networks").wrap(("</input>"));       
    });
    $("#rem_auth_networks").on("click", function(){              
        $("#auth_networks_"+count_auth_networks).remove();
        count_auth_networks -= 1;  
        if (count_auth_networks === -1) { count_auth_networks == 1; $("#auth_networks_"+count_auth_networks).remove();};        
    });         
})