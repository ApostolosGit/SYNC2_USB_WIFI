package gr.aircat.android

import android.app.Activity
import android.app.Dialog
import android.app.AlertDialog
import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.SeekBar
import android.widget.TextView
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.sin

/** Offline synthetic LAB playback; no device or network access. */
internal class LabReplayDialog(private val owner:Activity,private val audit:LabCsvAudit,
    private val report:String):Dialog(owner){
    private val events=audit.events()
    private val handler=Handler(Looper.getMainLooper())
    private var index=0
    private var direction=1
    private var playing=false
    private var speedIndex=1
    private val speeds=doubleArrayOf(.5,1.0,2.0,4.0,8.0)
    private var changing=false
    private lateinit var status:TextView
    private lateinit var seek:SeekBar
    private lateinit var picture:LabReplayView
    private val advance=Runnable{
        if(playing){
            val next=index+direction
            if(next in events.indices){index=next;refresh();schedule()}else pause()
        }
    }
    private fun dp(n:Int)=(n*owner.resources.displayMetrics.density).toInt()
    override fun onCreate(savedInstanceState:android.os.Bundle?){
        super.onCreate(savedInstanceState)
        setTitle("AIRCAT500 6.0 — LAB Replay")
        val root=LinearLayout(owner).apply{orientation=LinearLayout.VERTICAL;setPadding(dp(8),dp(8),dp(8),dp(8))}
        status=TextView(owner).apply{textSize=13f}
        root.addView(status)
        picture=LabReplayView(owner)
        root.addView(picture,LinearLayout.LayoutParams(-1,0,1f))
        seek=SeekBar(owner).apply{max=(events.size-1).coerceAtLeast(0)
            setOnSeekBarChangeListener(object:SeekBar.OnSeekBarChangeListener{
                override fun onStartTrackingTouch(bar:SeekBar){pause()}
                override fun onStopTrackingTouch(bar:SeekBar){}
                override fun onProgressChanged(bar:SeekBar,value:Int,fromUser:Boolean){
                    if(fromUser&&!changing&&events.isNotEmpty()){index=value;refresh()}
                }
            })
        }
        root.addView(seek)
        fun controls(vararg actions:Pair<String,()->Unit>){
            val row=LinearLayout(owner)
            actions.forEach{(label,action)->
                row.addView(Button(owner).apply{text=label;textSize=11f;setOnClickListener{action()}},
                    LinearLayout.LayoutParams(0,dp(46),1f))
            }
            root.addView(row)
        }
        controls("<< " to {play(-1)},"Prev" to {step(-1)},"Pause" to {pause()},"Next" to {step(1)},"Play >>" to {play(1)})
        controls("Speed" to {
            speedIndex=(speedIndex+1)%speeds.size;refresh();if(playing)schedule()
        },"Charts" to {pause();showCharts()},"Audit" to {
            pause();AlertDialog.Builder(owner).setTitle("LAB Audit").setMessage(report).setPositiveButton("OK",null).show()
        },"Close" to {dismiss()})
        setContentView(root)
        window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT,ViewGroup.LayoutParams.MATCH_PARENT)
        refresh()
    }
    private fun refresh(){
        val e=events.getOrNull(index)
        picture.event=e;picture.invalidate()
        status.text=if(e==null)"No synthetic events" else {
            val time=e.sourceUs?.let{"%.6f s".format(java.util.Locale.US,it/1e6)}?:"unknown"
            "${index+1}/${events.size}  ${e.kind} · source $time · segment ${e.segment?:"—"} · ${speeds[speedIndex]}x\n"+
            "Evaluated ${e.evaluated} | Observed miss ${e.missing} | Gaps ${e.gaps} | Ambiguous ${e.ambiguous}\n"+
            if(audit.hasIndex())"Synthetic LAB · Indexed CSV" else "Synthetic LAB · Legacy CSV (unmarked loss may be undetectable)"
        }
        changing=true;seek.progress=index;changing=false
    }
    private fun pause(){playing=false;handler.removeCallbacks(advance)}
    private fun step(delta:Int){pause();if(events.isNotEmpty()){index=(index+delta).coerceIn(events.indices);refresh()}}
    private fun play(dir:Int){pause();direction=dir;playing=true;schedule()}
    private fun schedule(){
        handler.removeCallbacks(advance)
        if(!playing||events.isEmpty())return
        val next=index+direction
        if(next !in events.indices){pause();return}
        val a=events[index];val b=events[next]
        val ms=if(a.sourceUs!=null&&b.sourceUs!=null&&a.segment==b.segment)abs(b.sourceUs-a.sourceUs)/1000.0 else 200.0
        handler.postDelayed(advance,(ms/speeds[speedIndex]).toLong().coerceIn(20L,2000L))
    }
    private fun showCharts(){
        val dialog=Dialog(owner);dialog.setTitle("6.0 LAB Charts")
        val root=LinearLayout(owner).apply{orientation=LinearLayout.VERTICAL}
        val title=TextView(owner).apply{text="Observed synthetic IDs; source timing only. No inference across gaps.";textSize=12f}
        root.addView(title)
        val charts=LabChartView(owner,audit)
        root.addView(charts,LinearLayout.LayoutParams(-1,0,1f))
        val button=Button(owner).apply{text="Next chart";setOnClickListener{charts.mode=(charts.mode+1)%4;charts.invalidate()}}
        root.addView(button)
        root.addView(Button(owner).apply{text="Close";setOnClickListener{dialog.dismiss()}})
        dialog.setContentView(root);dialog.show()
        dialog.window?.setLayout(-1,-1)
    }
    override fun dismiss(){pause();super.dismiss()}
}

private class LabReplayView(context:Context):View(context){
    var event:LabReplayEvent?=null
    private val p=Paint(Paint.ANTI_ALIAS_FLAG)
    override fun onDraw(c:Canvas){
        super.onDraw(c);c.drawColor(Color.WHITE)
        val cx=width/2f;val cy=height/2f;val r=(minOf(width,height)/2f-30f).coerceAtLeast(10f)
        val bounds=RectF(cx-r,cy-r,cx+r,cy+r)
        val e=event
        for(i in 0..31){
            p.style=Paint.Style.FILL;p.color=if(e!=null && (e.mask and (1L shl i))!=0L)Color.rgb(176,215,190) else Color.rgb(240,242,245)
            c.drawArc(bounds,-90f+i*11.25f,11.25f,true,p)
            p.style=Paint.Style.STROKE;p.color=Color.rgb(180,185,191);p.strokeWidth=1f
            c.drawArc(bounds,-90f+i*11.25f,11.25f,true,p)
            val t=(i+.5)*Math.PI/16
            p.style=Paint.Style.FILL;p.color=Color.DKGRAY;p.textSize=13f;p.textAlign=Paint.Align.CENTER
            c.drawText("%02X".format(i),cx+(r+17)*sin(t).toFloat(),cy-(r+17)*cos(t).toFloat()+4,p)
        }
        e?.sector?.let{
            val t=(it+.5)*Math.PI/16
            p.color=Color.rgb(32,92,145);p.strokeWidth=4f
            c.drawLine(cx,cy,cx+r*sin(t).toFloat(),cy-r*cos(t).toFloat(),p)
        }
        if(e?.kind in listOf("GAP","INVALID","AMBIGUOUS")){
            p.color=Color.rgb(150,80,20);p.textSize=22f;p.textAlign=Paint.Align.CENTER
            c.drawText(e?.kind.orEmpty(),cx,cy,p)
        }
    }
}

private class LabChartView(context:Context,private val audit:LabCsvAudit):View(context){
    var mode=0
    private val p=Paint(Paint.ANTI_ALIAS_FLAG)
    private val events=audit.events()
    private val rotations=events.mapIndexedNotNull{i,e->if(e.rotationMiss!=null)i to e else null}
    override fun onDraw(c:Canvas){
        super.onDraw(c);c.drawColor(Color.WHITE)
        val title=listOf("Observed missing IDs by sector","Missing IDs per evaluated interval","Source NORTH intervals (seconds)","Separate continuity counts")[mode]
        p.color=Color.DKGRAY;p.textSize=17f;p.textAlign=Paint.Align.CENTER
        c.drawText(title,width/2f,26f,p)
        val x0=52f;val y0=height-45f;val x1=width-16f;val y1=48f
        if(x1<=x0||y0<=y1)return
        val values=when(mode){
            0->audit.missingCounts().map{it.toDouble()}
            1->rotations.map{it.second.rotationMiss!!.toDouble()}
            2->rotations.mapNotNull{it.second.periodUs?.let{t->t/1e6}}
            else->listOf(audit.gaps.toDouble(),audit.ambiguous.toDouble(),audit.rotations.toDouble())
        }
        val ceiling=(values.maxOrNull()?:0.0).coerceAtLeast(1.0)
        fun y(v:Double)=y0-((y0-y1)*v/ceiling).toFloat()
        p.strokeWidth=1f;p.color=Color.GRAY;c.drawLine(x0,y0,x1,y0,p);c.drawLine(x0,y0,x0,y1,p)
        p.textSize=12f;p.textAlign=Paint.Align.RIGHT
        for(i in 0..4){
            val v=ceiling*i/4
            c.drawText("%.2f".format(java.util.Locale.US,v),x0-4,y(v)+4,p)
        }
        p.color=Color.rgb(51,111,151)
        if(mode==0||mode==3){
            val dx=(x1-x0)/values.size.coerceAtLeast(1)
            for((i,v) in values.withIndex()){
                val x=x0+i*dx
                p.color=Color.rgb(51,111,151);c.drawRect(x+1,y(v),x+dx-1,y0,p)
                if(mode==3||i%4==0){
                    p.color=Color.DKGRAY;p.textAlign=Paint.Align.CENTER;p.textSize=12f
                    c.drawText(if(mode==3)listOf("Gap","Ambiguous","Evaluated")[i] else "%02X".format(i),x+dx/2,y0+17,p)
                }
            }
        }else{
            for((i,e) in rotations){
                val v=if(mode==1)e.rotationMiss?.toDouble() else e.periodUs?.let{it/1e6}
                if(v!=null)c.drawCircle(x0+(x1-x0)*i/(events.size-1).coerceAtLeast(1),y(v),3f,p)
            }
            p.color=Color.DKGRAY;p.textAlign=Paint.Align.CENTER;p.textSize=12f
            c.drawText("Replay event index (points only; gaps not joined)",(x0+x1)/2,y0+20,p)
        }
    }
}
