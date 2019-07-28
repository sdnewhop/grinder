var map = L.map('map', {
  center: [10.0, 5.0],
  minZoom: 2,
  zoom: 2
});

L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
  attribution: 'Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community',
  subdomains: ['a', 'b', 'c']
}).addTo(map);

// var myURL = jQuery('script[src$="grinder.js"]').attr('src').replace('grinder.js', '');
myURL = "/";

var myIcon = L.icon({
  iconUrl: myURL + 'images/pin24.png',
  iconRetinaUrl: myURL + 'images/pin48.png',
  iconSize: [24, 39],
  iconAnchor: [11, 37],
  popupAnchor: [1, -23]
});

var markerClusters = L.markerClusterGroup();

function openInNewTab(url) {
  var win = window.open(url, '_blank');
  win.focus();
}

var source = $("#grinder-popup").html();
var template = Handlebars.compile(source);

for (var i = 0; i < markers.length; ++i) {
  if (markers[i].port === (443 || 8443)) {
    proto = 'https://';
  }
  else {
    proto = 'http://';
  }

  let HostAddress = proto + markers[i].ip + ':' + markers[i].port;
  let shodanAdditionalInfo = 'https://www.shodan.io/host/' + markers[i].ip;
  let censysAdditionalInfo = 'https://censys.io/ipv4/' + markers[i].ip;
  let googleMapsInfo = 'https://www.google.com/maps/search/?api=1&query=' + markers[i].lat + ',' + markers[i].lng;
  let ipLookup = 'https://extreme-ip-lookup.com/' + markers[i].ip;
  let zoomEyeAdditionalInfo = 'https://www.zoomeye.org/searchResult?q=' + markers[i].ip;

  let allLinks = 
  '<br/>' +
  '<a href="viewraw/' + i.toString() + '"><b>Open raw data </b></a>' + 
  '<br/>' + 
  '<a id="LinkToHost" title="Link to host" href="#" onclick="openInNewTab(\'' + HostAddress + '\');return false;"><b>Open host in browser</b></a>' + 
  '<br/>' + 
  '<a id="LinkToShodan" title="Link to Shodan" href="#" onclick="openInNewTab(\'' + shodanAdditionalInfo + '\');return false;"><b>Show in Shodan</b></a>' + 
  '<br/>' + 
  '<a id="LinkToCensys" title="Link to Censys" href="#" onclick="openInNewTab(\'' + censysAdditionalInfo + '\');return false;"><b>Show in Censys</b></a>' +
  '<br/>' +
  '<a id="LinkToZoomEye" title="Link to ZoomEye" href="#" onclick="openInNewTab(\'' + zoomEyeAdditionalInfo + '\');return false;"><b>Show in ZoomEye</b></a>' +
  '<br/>' +
  '<a id="LinkToGoogleMaps" title="Link to Google Maps" href="#" onclick="openInNewTab(\'' + googleMapsInfo + '\');return false;"><b>Show in Google Maps</b></a>' +
  '<br/>' +
  '<a id="LinkToIpLookup" title="Link to IP Lookup" href="#" onclick="openInNewTab(\'' + ipLookup + '\');return false;"><b>Show in IP Lookup</b></a>';

  let context = {
    vendor: markers[i].vendor || "Not detected",
    product: markers[i].product || "Not detected",
    version: markers[i].additional_info || "Not detected",
    ip: markers[i].ip,
    port: markers[i].port,
    protocol: markers[i].proto || "Not detected",
    latitude: Math.round(markers[i].lat * 1000) / 1000,
    longitude: Math.round(markers[i].lng * 1000) / 1000,
    content: allLinks,
  }
  var popup = template(context);

  var m = L.marker([markers[i].lat, markers[i].lng], {
          icon: myIcon
      })
      .bindPopup(popup);

  markerClusters.addLayer(m);
}

map.addLayer(markerClusters);