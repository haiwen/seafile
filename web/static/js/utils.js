function g(id) { return document.getElementById(id); }

var nav_a = g('nav').getElementsByTagName('a');
var lo = location.href.split('/')[3];
if (!lo) {
    nav_a[0].className = 'cur';
} else {
    for (var i = 0; i < nav_a.length - 1; i++) {
        if (nav_a[i].href == 'http://' + location.host + '/' + lo + '/') {
            nav_a[i].className = 'cur';
            break;
        }
    }
}
/**
 *display the current user or group on the left-panel of /msgs
 *by lingjun on 2011-6-8
 */
if (g('user-and-group')) {
    var user_and_group = g('user-and-group').getElementsByTagName('a');
    for (var i = 0; i < user_and_group.length; i++) {
        if (user_and_group[i].href == location.href.substring(0,user_and_group[i].href.length)) {
            user_and_group[i].parentNode.innerHTML = user_and_group[i].innerHTML;
            break;
        }
    }
}

/**
 *name:location_search
 *result:以{参数名：参数值，参数名：参数值，...}形式返回页面url中的参数信息
 *by lingjun on 2011-7-3
 */
function location_search() {
    var arr = location.search.substring(1).split('&');
    var new_search = {};
    for (var i = 0; i < arr.length; i++) {
        var new_arr = arr[i].split('=');
        new_search[new_arr[0]] = new_arr[1];
    }
    return new_search;
}
//for tables
$(function() {
    $("table tr:nth-child(even)").addClass("even");
    $("table tr:nth-child(odd)").addClass("odd");
    $("table tr th").parent().removeClass("odd");
})
