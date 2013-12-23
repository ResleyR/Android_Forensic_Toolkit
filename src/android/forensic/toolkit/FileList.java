/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;

import java.util.ArrayList;
import javax.xml.bind.annotation.*;
/**
 *
 * @author Resley Rodrigues
 */

@XmlRootElement(name = "FileList", namespace = "aftk")
@XmlAccessorType(XmlAccessType.FIELD)
public class FileList {
    @XmlElementWrapper(name = "list")
    
    @XmlElement(name = "File")
    ArrayList <FileRecord> file;
    
    public void setFile(ArrayList <FileRecord> File) {
        this.file = File;
    }
    
    public ArrayList <FileRecord> getFile() {
        return file;
    }
}
    