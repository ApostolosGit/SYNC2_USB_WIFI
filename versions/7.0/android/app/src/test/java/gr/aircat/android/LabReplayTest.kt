package gr.aircat.android
import org.junit.Test
import org.junit.Assert.*

class LabReplayTest{
    private fun read(seq:List<Int>,deleted:Int?=null):LabCsvAudit{
        val s=StringBuilder("capture_event,capture_segment,source_us,frame_no,udp_payload_hex,capture_connection,reason,capture_index\n")
        seq.forEachIndexed{i,sec->
            val n=i+1
            if(n!=deleted){
                if(sec==-2)s.append("GAP,0,,,,LAB TCP v5,disconnect,$n\n")
                else{
                    val hex=if(sec==-1)"1940FD000000" else "0C40FD%02X".format(sec)
                    s.append("FRAME,0,${n*125000L},$n,$hex,LAB TCP v5,,$n\n")
                }
            }
        }
        return LabCsvAudit.read(s.toString().reader(),retainTimeline=true)
    }
    @Test fun clean(){val a=read(listOf(-1)+(0..31)+listOf(-1));assertEquals(0L,a.events().last().rotationMiss);assertEquals(4125000L,a.events().last().periodUs)}
    @Test fun gap(){val a=read(listOf(-1,0,1,-2,20,-1)+(0..31)+listOf(-1));val e=a.events().first{it.kind=="GAP"};assertEquals(0L,e.mask);assertNull(e.sourceUs);assertEquals(0L,a.observedMiss);assertEquals(1L,a.rotations)}
    @Test fun deleted(){val a=read(listOf(-1)+(0..31)+listOf(-1),10);assertTrue(a.events().any{it.kind=="INVALID"});assertEquals(0L,a.observedMiss)}
    @Test fun missed(){val a=read(listOf(-1)+(0..31).filter{it!=9}+listOf(-1));assertEquals(1L,a.events().last().rotationMiss);assertEquals(1L,a.missingCounts()[9])}
    @Test fun wrap(){val a=read(listOf(-1,0,1,0,-1));assertTrue(a.events().any{it.kind=="AMBIGUOUS"});assertEquals(0L,a.rotations)}
    @Test fun partial(){assertEquals(0L,read(listOf(-1,0,1)).rotations)}
}
