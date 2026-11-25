package gr.aircat.android
import org.junit.Test
import org.junit.Assert.*
class SharedLabTest{
    @Test fun commonFixture(){
        fun read(retain:Boolean):LabCsvAudit = requireNotNull(javaClass.getResourceAsStream("/shared_lab.csv")).bufferedReader().use{LabCsvAudit.read(it,retain)}
        for(a in listOf(read(false),read(true))){
            assertEquals(100L,a.frames);assertEquals(2L,a.gaps);assertEquals(1L,a.invalidRows)
            assertEquals(2L,a.interrupted);assertEquals(3L,a.rotations);assertEquals(2L,a.perfect)
            assertEquals(1L,a.observedMiss);assertEquals(1L,a.missingCounts()[31])
        }
    }
    @Test fun longOffline(){
        val a=LabCsvAudit()
        repeat(33001){i->
            val s=i%33
            val p=if(s==0)"1940FD000000" else "0C40FD%02X".format(s-1)
            a.accept("FRAME","0",(i*125000L).toString(),i.toString(),p,"LAB TCP v5")
        }
        assertEquals(33001L,a.frames);assertEquals(1000L,a.perfect);assertEquals(0L,a.gaps);assertEquals(0L,a.observedMiss)
    }
}
