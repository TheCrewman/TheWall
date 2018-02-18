var accordion_built = false;

function divUpdater(http_filter, adsmasher)
{
  if (http_filter)
  {
    $.get("HttpFilter.php", function(msg) {
      $(".accordion_content").html("");

      connections = msg.split("<br/>")

      for (i = 0; i < connections.length; i++)
      {
        src_ip = connections[i].split(" --> ")[0].substring(connections[i].split(" --> ")[0].indexOf("] ") + 1);

        for (j = 0; j < connections.length; j++)
        {
          dst_ip = connections[j].split(" --> ")[1];

          if (src_ip == connections[j].split(" --> ")[0].substring(connections[j].split(" --> ")[0].indexOf("] ") + 1))
          {
            time = connections[j].split(" --> ")[0].substring(0, connections[j].split(" --> ")[0].indexOf("]") + 1);

            if ($("#accordion_content_" + i).html() != "")
            {
              $("#accordion_content_" + i).html($("#accordion_content_" + i).html() + "<br/><b>" + time + "</b>   " + dst_ip);
            }
            else
            {
              $("#accordion_content_" + i).html("<b>" + time + "</b>   " + dst_ip);
            }
          }
        }
      }
    });
  }

  if (adsmasher)
  {
    $.get("AdSmasher.php", function(msg) {
      $("#smashed_ads_content").html(msg);
    });
  }
}

function findURL(str_to_search)
{
  str_to_show = []

  $.get("AdSmasher.php", function(msg) {
    for (i = 0; i < msg.split("<br/>").length; i++)
    {
      if ($("#case_sensitive").prop("checked"))
      {
        if (msg.split("<br/>")[i].substring("DNS requests blocked for ".length, msg.split("<br/>")[i].indexOf(":")).includes(str_to_search))
        {
          str_to_show.push(msg.split("<br/>")[i]);
        }
      }
      else
      {
        if (msg.split("<br/>")[i].substring("DNS requests blocked for ".length, msg.split("<br/>")[i].indexOf(":")).toLowerCase().includes(str_to_search.toLowerCase()))
        {
          str_to_show.push(msg.split("<br/>")[i]);
        }
      }
    }

    $("#smashed_ads_content").html(str_to_show.join("<br/>"));
  });
}

function sortSourceIPs()
{
  $.get("HttpFilter.php", function(msg) {
    connections = msg.split("<br/>");

    src_ips = [];

    for (i = 0; i < connections.length; i++)
    {
      src_ip = connections[i].split(" --> ")[0].substring(connections[i].split(" --> ")[0].indexOf("] ") + 1);

      if ((src_ips.indexOf(src_ip) < 0) && (src_ip != ""))
      {
        $("#src_ips").append("<h3>" + src_ip + "</h3><div class=\"accordion_content\" id=\"accordion_content_" + i + "\"></div>");
        src_ips.push(src_ip);

        for (j = 0; j < connections.length; j++)
        {
          dst_ip = connections[j].split(" --> ")[1];

          if (src_ip == connections[j].split(" --> ")[0].substring(connections[j].split(" --> ")[0].indexOf("] ") + 1))
          {
            time = connections[j].split(" --> ")[0].substring(0, connections[j].split(" --> ")[0].indexOf("]") + 1);

            if ($("#accordion_content_" + i).html() != "")
            {
              $("#accordion_content_" + i).html($("#accordion_content_" + i).html() + "<br/><b>" + time + "</b>   " + dst_ip);
            }
            else
            {
              $("#accordion_content_" + i).html("<b>" + time + "</b>   " + dst_ip);
            }
          }
        }
      }
    }

  }).done(function() {
    // Così non ricostruisce accordion e tabs (utile se si riuscisse ad aggiornare il contenuto degli accordion ogni tot secondi).
    if (accordion_built == false)
    {
      $("#src_ips").accordion({
        header: "h3",
        collapsible: true,
        heightStyle: "content"
      });

      accordion_built = true;
    }

    //$("#main_box").tabs();
  });
}

// A lungo andare occupa tanta RAM lato client
function autoRefresh()
{
  if ($("#auto_refresh").prop("checked"))
  {
    $("#refresh_btn").attr("disabled", "");

    interval_id = setInterval(function() {
        divUpdater(true, false);
        findURL($("#url_finder").val());
    }, 1000);
  }
  else
  {
    if (typeof interval_id != "undefined")
    {
      clearInterval(interval_id);
      divUpdater(true, true);
    }

    $("#refresh_btn").removeAttr("disabled");
  }
}

function checkForNewHosts()
{
  $("#src_ips").accordion("destroy");
  accordion_built = false;
  $("#src_ips").html("");
  sortSourceIPs();
}

$(document).ready(function() {
  $("#main_box").tabs();

  sortSourceIPs();
  findURL($("#url_finder").val());
  autoRefresh();
});

$("#refresh_btn").click(function() {
  divUpdater(true, true);
});

$("#auto_refresh").click(function() {
  autoRefresh();
});

$("#check_new_hosts_btn").click(function() {
  checkForNewHosts();
});

$("#url_finder").keyup(function() {
  findURL($("#url_finder").val());
});

$("#case_sensitive").click(function() {
  findURL($("#url_finder").val());
});
