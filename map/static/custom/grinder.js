var map = L.map('map', {
    center: [10.0, 5.0],
    minZoom: 2,
    zoom: 2
});

var myIcon = L.icon({
    iconUrl: '/images/pin24.png',
    iconRetinaUrl: '/images/pin48.png',
    iconSize: [24, 39],
    iconAnchor: [11, 37],
    popupAnchor: [1, -23]
});

L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
    attribution: 'Tiles &copy; Esri &mdash; Source: Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP, and the GIS User Community',
    subdomains: ['a', 'b', 'c']
}).addTo(map);

var source = document.getElementById('grinder-popup').innerHTML;
var template = Handlebars.compile(source);
var markerClusters = L.markerClusterGroup();

fetch(window.location.origin + '/api/viewall')
    .then(function(response) {
        return response.json();
    })
    .then(function(markers) {
        for (var i = 0; i < markers.length; ++i) {
            let proto = (markers[i].port === 443 ||
                markers[i].port === 8443) ? 'https://' : 'http://';
            let context = {
                index: i.toString(),
                basic: {
                    vendor: markers[i].vendor || 'Not detected',
                    product: markers[i].product || 'Not detected',
                    version: markers[i].additional_info || 'Not detected',
                    ip: markers[i].ip,
                    port: markers[i].port,
                    protocol: markers[i].proto || 'Not detected',
                    latitude: Math.round(markers[i].lat * 1000) / 1000,
                    longitude: Math.round(markers[i].lng * 1000) / 1000,
                },
                api: {
                    raw: 'api/viewraw/' + i.toString(),
                },
                additionalContent: {
                    host: proto + markers[i].ip + ':' + markers[i].port,
                    shodan: 'https://www.shodan.io/host/' + markers[i].ip,
                    censys: 'https://censys.io/ipv4/' + markers[i].ip,
                    zoomeye: 'https://www.zoomeye.org/searchResult?q=' + markers[i].ip,
                    googlemaps: 'https://www.google.com/maps/search/?api=1&query=' + markers[i].lat + ',' + markers[i].lng,
                    iplookup: 'https://extreme-ip-lookup.com/' + markers[i].ip,
                },
            }

            let popup = template(context);
            let m = L.marker([markers[i].lat, markers[i].lng], {
                    icon: myIcon
                })
                .bindPopup(popup);
            m.marker_index = i;
            markerClusters.addLayer(m);
        }

        map.addLayer(markerClusters);
        markerClusters.on('popupopen', function(event) {
            setTimeout(function() {
                console.log(event.layer.marker_index);
                ping(event.layer.marker_index);
                document.getElementById('force-refresh-ping-status').addEventListener('click', function() {
                    ping(event.layer.marker_index);
                }, false);
            }, 1500);
        });
    });