/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;
import javax.swing.text.Document;

/**
 *
 * @author Resley Rodrigues
 */
public class FAT32 extends FAT12 {
//Import Default FAT values from base class
//FAT32 specific values
    //11-27   (as before)

    long hidden_sectorsL;           //28-31
    long total_sectorsL;            //32-35
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
    int logical_drive_number;       //64                for use with INT 13, e.g. 0 or 0x80
    //65      Reserved - used to be Current Head (used by Windows NT)
    int extened_signature;          //66                Extended signature (0x29)
    //                  Indicates that the three following fields are present.
    long serial_number;             //67-70
    String label = "";              //71-81
    String type = "";               //82-89
    //510-511   Signature (imported)
    private JFrame win;
    long first_data_sector;
    //Additional variables
    String src_file = "res/file.png";
    String deleted_file = "res/deleted_file.png";
    String folder = "res/folder.png";
    String deleted_folder = "res/deleted_folder.png";
    String title = "";
    String body = "";
    Boolean deleted = null;

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

    private String checkIfDeleted(int attribute) {
        String attrib = "<td align='left'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
        switch (attribute) {
            case 0x01:
                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("R");     // READ ONLY
                break;
            case 0x02:
                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("&nbsp;H");    // HIDDEN
                break;
            case 0x03:
                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("RH");    // READ ONLY & HIDDEN
                break;
            case 0x04:
                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("&nbsp;&nbsp;S");    // SYSTEM
                break;
            case 0x05:
                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("R&nbsp;S");    // READ ONLY & SYSTEM
                break;
            case 0x06:
                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("&nbsp;HS");    // HIDDEN & SYSTEM
                break;
            case 0x07:
                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("RHS");    // READ ONLY, HIDDEN & SYSTEM
                break;
            case 0x10:
                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
//              DIRECTORY
                break;
            case 0x11:
                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("R");     // READ ONLY DIRECTORY
                break;
            case 0x12:
                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("&nbsp;H");    // HIDDEN DIRECTORY
                break;
            case 0x13:
                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("RH");    // READ ONLY & HIDDEN DIRECTORY
                break;
            case 0x14:
                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("&nbsp;&nbsp;S");    // SYSTEM DIRECTORY
                break;
            case 0x15:
                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("R&nbsp;S");    // READ ONLY & SYSTEM DIRECTORY
                break;
            case 0x16:
                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("&nbsp;HS");    // HIDDEN & SYSTEM DIRECTORY
                break;
            case 0x17:
                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("RHS");    // READ ONLY, HIDDEN & SYSTEM DIRECTORY
                break;
            default:
                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                break;

        }
        attrib = attrib.concat("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td>");
        return attrib;
    }

    private void recalulate(javax.swing.JTextArea a, byte ar[]) {
        FileWriter fWriter = null;
            BufferedWriter writer = null;
            try {
                StringBuilder contentBuilder = new StringBuilder();
                try {
                    try (BufferedReader in = new BufferedReader(new FileReader("src/res/cache_template.html"))) {
                        String str;
                        while ((str = in.readLine()) != null) {
                            contentBuilder.append(str);
                        }
                    }
                } catch (IOException ey) {
                }
                String htmlString = contentBuilder.toString();
                File file = new File("src/cache/" + title + ".html");
                file.getParentFile().mkdirs();
                fWriter = new FileWriter(file);
                writer = new BufferedWriter(fWriter);


                int j = 0;
                int old_j = 0, new_j;
                filelister:
                while (j < 7168) {
                    System.out.println(j);
                    int attribute = Utils.hexToInt(Utils.hex(ar[i = j + 11]), "0");    //Byte 11 attribute
                    
                    switch (attribute) {
                        case 0x0F:
//               LongFileName
                            j += 32;
                            System.out.println("Skipped: " + j);
                            continue filelister;
                        default:   
                             String attrib;
                            body = body.concat("<tr>");
                            if (Utils.hexToInt(Utils.hex(ar[j]), "0") == 0xE5) {
                                body = body.concat("<td align='left' style='color:red;'>");
                                deleted = true;
                            } else {
                                body = body.concat("<td align='left' style='color:black;'>");
                                deleted = false;
                            }
                            switch (Utils.hexToInt(Utils.hex(ar[j + 6]), "0")) {
                                case 0x7E:
                                    new_j = j;
                                    j -= 32;


//                            a.append("DELETED\t");
                                    
                                   attrib = checkIfDeleted(attribute);
                                    String temp;
                                    while (j > old_j) {
                                        for (i = j + 2; i <= (j + 10); i += 3) {
                                            temp = String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i])));
                                            System.out.print(temp+"  ");
                                            if (temp.equals("\uFFFF")) {
                                                break;
                                            }
                                            body = body.concat(temp);
                                        }
                                        for (i = j + 15; i <= (j + 25); i += 3) {
                                            temp = String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i])));
                                            System.out.print(temp+"  ");
                                            if (temp.equals("\uFFFF")) {
                                                break;
                                            }
                                            body = body.concat(temp);
                                        }
                                        for (i = j + 29; i <= (j + 31); i += 3) {
                                            temp = String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i])));
                                            System.out.print(temp+"  ");
                                            if (temp.equals("\uFFFF")) {
                                                break;
                                            }
                                            body = body.concat(temp);
                                        }
                                        j -= 32;
                                    }
                                    j = new_j;
                                    body = body.concat("</td>");
                                    break;
                                default:
                                    attrib = checkIfDeleted(attribute);
                                    for (i = j; i <= (j + 10); i++) //Byte 0-10 filename
                                    {
                                        body = body.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
//                            a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                                    }
                                    break;
                            }
                            body = body.concat(attrib);
                            i = j + 20;           //Byte 20-21 starting sector high order 
                            //Byte 26-27 starting sector low  order 
                            a.append("@ sector " + String.format("%04X\t", Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i]), Utils.hex(ar[i = j + 26]), Utils.hex(ar[++i]), "0", "0", "0", "0")));
                            //Bytes 28-31 file size
                            body = body.concat("<td align='left'>" + Utils.getSize(Utils.hexToInt(Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), "0", "0", "0", "0")) + "</td>");
                            //a.append(Utils.getSize(Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), "0", "0", "0", "0")) + "\n");
                            old_j = j;
                            break;



                        case 0x08:
                            body = body.concat("<tr>");
                            body = body.concat("<td align='left' colspan='3'><b>");
                            for (i = j; i <= (j + 10); i++) //Byte 0-10 filename
                            {
                                body = body.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                            }
                            //a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                            body = body.concat("&#09; VOLUME ID</b></td>");
                            //a.append("\t VOLUME ID\n");
                            break;
                    }
                    //increment by 32 to go to next file entry.
                    j += 32;
                    body = body.concat("</tr>");
                }
                body = body.concat("</table>");

                htmlString = htmlString.replace("$title", title);
                htmlString = htmlString.replace("$body", body);
                writer.write(htmlString);
                writer.newLine(); //this is not actually needed for html files - can make your code more readable though 
                writer.close(); //make sure you close the writer object 
                
            } catch (Exception ex) {
                Logger.getLogger(FAT32.class.getName()).log(Level.SEVERE, null, ex);
                System.err.println("Exception Occured");
            }
    }
    
    public void readFAT(javax.swing.JTextArea a, javax.swing.JEditorPane e, Boolean forceReCalc) throws IOException {
        byte[] ar;

        first_data_sector = reserved_sectors + (number_of_FAT_copies * sectors_per_FATL);
        ar = new byte[((int) sectors_per_FATL) * bytes_per_Sector];//16*16*100];
        Arrays.fill(ar, (byte) 0);
        int jumpto = (int) (first_cluster - 2 + first_data_sector) * bytes_per_Sector;
        address = reserved_sectors * bytes_per_Sector;
        diskAccess.seek(jumpto);
        System.out.println(diskAccess.getFilePointer());
        diskAccess.read(ar);

        title = "" + serial_number;
        body = "<table style='border-spacing: 10px 0;'>";
        File cachedFile = new File("src/cache/" + title + ".html");
        e.setEditable(false);
        e.setContentType("text/html");
        if (cachedFile.exists()&&!forceReCalc) {
            e.setPage("file:///" + cachedFile.getAbsoluteFile());
            MainJFrame.re_calc.setVisible(true);
 } else {
            recalulate(a, ar);
            Document doc = e.getDocument();
            doc.putProperty(Document.StreamDescriptionProperty, null);
            e.setPage("file:///" + cachedFile.getAbsoluteFile());
        }
    }
}