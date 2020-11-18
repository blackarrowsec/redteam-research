function doGet(e) {
  var url = decodeURIComponent(e.parameter.url);
  try {
    var response = UrlFetchApp.fetch(url);
  } catch (e) {
    return e.toString();
  }
  var cookie = response.getAllHeaders()['Set-Cookie']
  return ContentService.createTextOutput(cookie);
}
  
function doPost(e) {
  Logger.log('[+] Post Done!');
  payload = "";
  
  if(e.postData){
    payload = e.postData.getDataAsString();
  }
  else {
    Logger.log("[-] Post Error :(")
    payload = "!!Error";
  }

  var options = {
  'method' : 'post',
  'payload' : payload
  };
 
 var url = decodeURIComponent(e.parameter.url);
  try {
    var response = UrlFetchApp.fetch(url,options);
  } catch (e) {
    return e.toString();
  }
 
  Logger.log('UrlFetch Response: %s',response);
  return ContentService.createTextOutput(response.getContentText());
}
  