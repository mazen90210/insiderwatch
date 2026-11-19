let activityChart;

function number(value){return Number(value||0).toLocaleString()}

function setText(id,value){
    document.getElementById(id).textContent=value;
}

function renderRisk(results){
    const body=document.getElementById("risk-table");
    if(!results || !results.length){
        body.innerHTML='<tr><td colspan="5" class="empty">No AI profiles available</td></tr>';
        return;
    }
    body.innerHTML=results.slice(0,10).map(item=>{
        const level=(item.threat_level||"Low").toLowerCase();
        return `<tr>
            <td>${item.host||"Unknown"}</td>
            <td>${item.username||"Unknown"}</td>
            <td class="score">${number(item.risk_score)}/100</td>
            <td><span class="badge-level level-${level}">${item.threat_level}</span></td>
            <td>${item.is_anomaly?"<span style='color:#ff8394'>Detected</span>":"<span style='color:#66dfb4'>Normal</span>"}</td>
        </tr>`;
    }).join("");
}

function renderEvents(events){
    const body=document.getElementById("events-table");
    if(!events || !events.length){
        body.innerHTML='<tr><td colspan="5" class="empty">No events found</td></tr>';
        return;
    }
    body.innerHTML=events.map(e=>`<tr>
        <td>${e.ts?new Date(e.ts).toLocaleString():"—"}</td>
        <td>${e.host||"—"}</td>
        <td>${e.username||"—"}</td>
        <td>${e.event_type||"—"}</td>
        <td>${e.message||"—"}</td>
    </tr>`).join("");
}

function renderChart(stats){
    const labels=Object.keys(stats).filter(key=>key!=="total_events");
    const values=labels.map(key=>Number(stats[key]||0));

    if(activityChart) activityChart.destroy();

    activityChart=new Chart(document.getElementById("activityChart"),{
        type:"bar",
        data:{labels,datasets:[{label:"Events",data:values,backgroundColor:"#6688ff",borderRadius:5,maxBarThickness:38}]},
        options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{
            x:{ticks:{color:"#91a0ba",font:{size:10}},grid:{display:false}},
            y:{beginAtZero:true,ticks:{color:"#71819d",precision:0},grid:{color:"#253149"}}
        }}
    });
}

async function loadDashboard(){
    try{
        const [statsResponse,aiResponse,eventsResponse]=await Promise.all([
            fetch("/api/stats"),
            fetch("/api/ai/analyze"),
            fetch("/api/events")
        ]);

        if(!statsResponse.ok || !aiResponse.ok || !eventsResponse.ok)
            throw new Error("API request failed");

        const stats=await statsResponse.json();
        const ai=await aiResponse.json();
        const events=await eventsResponse.json();

        // Use the actual total from the API instead of summing all statistics.
        const total=Number(stats.total_events||0);

        setText("total-events",number(total));
        setText("failed-logins",number(stats.failed_login));
        setText("profiles",number(ai.profiles_analyzed));

        const results=ai.results||[];

        setText("anomalies",number(results.filter(x=>x.is_anomaly).length));

        ["Critical","High","Medium","Low"].forEach(level=>{
            setText(
                level.toLowerCase()+"-count",
                number(results.filter(x=>x.threat_level===level).length)
            );
        });

        setText(
            "ai-status",
            ai.model_trained
                ?"AI ENGINE ONLINE · ISOLATION FOREST TRAINED"
                :"AI ENGINE ONLINE · RULE-BASED MODE"
        );

        renderRisk(results);
        renderEvents(events.events||[]);
        renderChart(stats);

        setText("last-updated","Last updated: "+new Date().toLocaleTimeString());

    }catch(error){
        setText("ai-status","Unable to load dashboard data. Check API connection.");
        console.error(error);
    }
}

loadDashboard();
setInterval(loadDashboard,15000);