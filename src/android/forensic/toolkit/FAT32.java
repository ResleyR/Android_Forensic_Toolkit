package android.forensic.toolkit;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

/**
 *
 * @author Resley Rodrigues
 */
public class FAT32 extends FAT16 {
//Import Default FAT values from base class
//FAT32 specific values
    //11-35   (as before)
    long sectors_per_FATL;          //36-39
    int mirror_flags;               //40-41
//        Bits 0-3: number of active FAT (if bit 7 is 1)
//        Bits 4-6: reserved
//        Bit 7: one: single active FAT; zero: all FATs are updated at runtime
//        Bits 8-15: reserved
    int fs_version;                 //42-43
    long first_cluster;             //44-47             Usually 2
    int fs_info;                    //48-49             Filesystem information sector number in FAT32 reserved area (usually 1)
    int backup_bootsector;          //50-51             Backup boot sector location or 0 or 0xffff if none (usually 6)
    //52-63   Reserved
//    int logical_drive_number;       //64      36 in FAT12/16          for use with INT 13, e.g. 0 or 0x80
    //65      Reserved - used to be Current Head (used by Windows NT)
//    int extened_signature;          //66        38 in FAT12/16          Extended signature (0x29)
//    //                  Indicates that the three following fields are present.
//    long serial_number;             //67-70     39-42 in FAT12/16
//    String label = "";              //71-81     43-53 in FAT12/16
//    String type = "";               //82-89     54-61 in FAT12/16
    //510-511   Signature (imported)

    @Override
    public void getBPB(String path) throws FileNotFoundException, IOException {
        super.getBPB(path);
        //default values completed... FAT32 specific values begin
        i = 28;
        hidden_sectorsL = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));   //28-31
        total_sectorsL = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));    //32-35
        sectors_per_FATL = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));  //36-39
        mirror_flags = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                                                        //40-41
        fs_version = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                                                          //42-43
        first_cluster = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));     //44-47
        fs_info = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                                                             //48-49
        backup_bootsector = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                                                   //50-51
        i = 64;     //52-63   Reserved
        logical_drive_number = Utils.hexToInt(Utils.hex(content[i++]), "00");                                                                   //64
        i++;        //65      Reserved - used to be Current Head (used by Windows NT)
        extened_signature = Utils.hexToInt(Utils.hex(content[i++]), "00");  //66  Extended signature (0x29) Indicates that the three following fields are present.
        serial_number = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));    //67-70   Serial number of partition
        for (i = 71; i <= 81; i++) {
            label = label.concat(String.valueOf(Utils.hexToText(Utils.hex(content[i]))));                                                        //71-81   Volume label
        }
        for (i = 82; i <= 89; i++) {
            type = type.concat(String.valueOf(Utils.hexToText(Utils.hex(content[i]))));                                                         //82-89   Filesystem type ("FAT32   ")
        }
        signature = Utils.hex(content[i = 510]) + Utils.hex(content[i = 511]);
    }

    @Override
    public void printBPB(javax.swing.JTextArea a, javax.swing.JTextArea b) {
        b.append("\t\t 0\t 1\t 2\t 3\t 4\t 5\t 6\t 7\t\t 8\t 9\t A\t B\t C\t D\t E\t F");
        for (i = 0; i < bytes_per_Sector; i++) {
            if (i % 16 == 0) {
                b.append(String.format("\n%07X0\t", address++));
            } else if (i % 8 == 0) {
                b.append("\t");
            }
            b.append(Utils.hex(content[i]) + "\t");
        }
        a.append(String.format("%-22s\t%s", "Jump Instruction", jump_instruction));
        a.append(String.format("\n%-22s\t\t%s", "OEM", OEM_name));
        a.append(String.format("\n%-22s\t%d", "Bytes per Sector", bytes_per_Sector));
        a.append(String.format("\n%-22s\t%d", "Sectors per Cluster", sectors_per_cluster));
        a.append(String.format("\n%-22s\t%d", "Reserved Sectors", reserved_sectors));
        a.append(String.format("\n%-22s\t%d", "Number of FAT Copies", number_of_FAT_copies));
        a.append(String.format("\n%-22s\t%d", "Root Directory Entries", number_of_root_directory_entries));
        if (total_sectors == 0) {
            a.append(String.format("\n%-22s\t%d", "Total Sectors", total_sectorsL));
        } else {
            a.append(String.format("\n%-22s\t%d", "Total Sectors", total_sectors));
        }
        a.append(String.format("\n%-22s\t%s", "Media Descriptor", media_descriptor));
        if (sectors_per_FAT == 0) {
            a.append(String.format("\n%-22s\t%d", "Sectors per FAT", sectors_per_FATL));
        } else {
            a.append(String.format("\n%-22s\t%d", "Sectors per FAT", sectors_per_FAT));
        }
        a.append(String.format("\n%-22s\t%d", "Sectors per Track", sectors_per_track));
        a.append(String.format("\n%-22s\t%d", "Number of Heads", number_of_heads));
        if (hidden_sectors == 0) {
            a.append(String.format("\n%-22s\t%d", "Hidden Sectors", hidden_sectorsL));
        } else {
            a.append(String.format("\n%-22s\t%d", "Hidden Sectors", hidden_sectors));
        }
        a.append(String.format("\n%-22s\t%d", "FAT Mirroring disabled", mirror_flags));
        a.append(String.format("\n%-22s\t%d", "FileSystem Version", fs_version));
        a.append(String.format("\n%-22s\t%d", "First Cluster Location", first_cluster));
        a.append(String.format("\n%-22s\t%d", "FileSystem Info Sector", fs_info));
        a.append(String.format("\n%-22s\t%d", "Backup BootSector", backup_bootsector));
        a.append(String.format("\n%-22s\t%d", "Logical Drive Number", logical_drive_number));
        a.append(String.format("\n%-22s\t%X", "Extended Signature", extened_signature));
        a.append(String.format("\n%-22s\t%d", "Serial Number", serial_number));
        a.append(String.format("\n%-22s\t\t%s", "Signature", signature));
    }

    @Override
    public void readFAT(javax.swing.JTextArea a, final javax.swing.JList list, Boolean forceReCalc) throws IOException, JAXBException {
        first_data_sector = reserved_sectors + (number_of_FAT_copies * sectors_per_FATL);
        jumpto = (int) (first_cluster - 2 + first_data_sector) * bytes_per_Sector;
        diskAccess.seek(jumpto);
        title = "" + serial_number;
        File cachedXML = new File("src/cache/" + title + ".xml");
        File cachedDAT = new File("src/cache/" + title + ".dat");
        if (cachedXML.exists() && cachedDAT.exists() && !forceReCalc) {
            FileReader dat = new FileReader(cachedDAT);
            a.read(dat, null);
            JAXBContext context = JAXBContext.newInstance(FileList.class);
            Unmarshaller um = context.createUnmarshaller();
            FileList filesList = (FileList) um.unmarshal(new FileReader(cachedXML));
            if (filesList != null) {
                System.out.println("Unmarshalled");
            } else {
                System.err.println("Error in unmarshallling");
            }
            files = filesList.getFile();
            listFiles(list);
            MainJFrame.re_calc.setVisible(true);
        } else {
            byte[] ar;
            ar = new byte[((int) sectors_per_FATL) * bytes_per_Sector];//16*16*100];
            Arrays.fill(ar, (byte) 0);
            files = new ArrayList<>();
            address = reserved_sectors * bytes_per_Sector;
            diskAccess.seek(jumpto);
            diskAccess.read(ar);
            recalulate(a, ar);
            listFiles(list);
        }
        diskAccess.close();
        System.out.println("closed diskAccess");
    }
}