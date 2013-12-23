/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;

import javax.xml.bind.annotation.*;
/**
 *
 * @author Resley Rodrigues
 */
@XmlRootElement(name = "File")
public class FileRecord {
    String img;
    String name;
    String attributes;
    String filesize;
    int foundAt;
    long startSector;
    
    public String getImage() {
        return img;
    }
    
    @XmlElement
    public void setImage(String Image) {
        this.img = Image;
    }
    
    public String getName() {
             return name;
        }
    @XmlElement
    public void setName(String Name) {
             this.name = Name;
        }
    public String getAttributes() {
        return attributes;
    }
    @XmlElement
    public  void setAttributes(String Attributes) {
        this.attributes = Attributes;
    }
    public String getFileSize() {
        return filesize;
    }
    @XmlElement
    public  void setFileSize(String FileSize) {
        this.filesize = FileSize;
    }
    public int getFoundAt() {
        return foundAt;
    }
    @XmlElement
    public void setFoundAt(int Sector) {
        this.foundAt = Sector;
    }
    public long getStartSector() {
        return startSector;
    }
    @XmlElement
    public void setStartSector(long Sector) {
        this.startSector = Sector;
    }
    
    
}
