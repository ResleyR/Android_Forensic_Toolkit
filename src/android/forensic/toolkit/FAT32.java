/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;

import java.awt.Color;
import java.awt.FlowLayout;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

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

    long first_data_sector;
    static int jumpto;  //root directory location
    //Additional variables
    private static final String src_file = "/res/file.png";
    private static final String deleted_file = "/res/deleted_file.png";
    private static final String folder = "/res/folder.png";
    private static final String deleted_folder = "/res/deleted_folder.png";
    private static final String hidden_file = "/res/hidden_file.png";
    private static final String hidden_deleted_file = "/res/deleted_hidden_file.png";
    private static final String hidden_folder = "/res/hidden_folder.png";
    private static final String hidden_deleted_folder = "/res/deleted_hidden_folder.png";
    String title = "";
    String body = "";
    Boolean deleted = null;
    String Image = "";
    static ArrayList <FileRecord> files = new ArrayList<>();


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
//        String attrib = "<td align='left'>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
//        System.out.println("Attribute in checkIfDeleted: "+attribute);
        String attrib = "";
        switch (attribute) {
            case 0x01:
                Image = ((deleted) ? deleted_file : src_file);
//                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("R  ");     // READ ONLY
                break;
            case 0x02:
                Image = ((deleted) ? hidden_deleted_file : hidden_file);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_file : hidden_file) + "' />");
                attrib = attrib.concat(" H ");    // HIDDEN
                break;
            case 0x03:
                Image = ((deleted) ? hidden_deleted_file : hidden_file);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_file : hidden_file) + "' />");
                attrib = attrib.concat("RH ");    // READ ONLY & HIDDEN
                break;
            case 0x04:
                Image = ((deleted) ? deleted_file : src_file);
//                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("  S");    // SYSTEM
                break;
            case 0x05:
                Image = ((deleted) ? deleted_file : src_file);
//                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("R S");    // READ ONLY & SYSTEM
                break;
            case 0x06:
                Image = ((deleted) ? hidden_deleted_file : hidden_file);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_file : hidden_file) + "' />");
                attrib = attrib.concat(" HS");    // HIDDEN & SYSTEM
                break;
            case 0x07:
                Image = ((deleted) ? hidden_deleted_file : hidden_file);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_file : hidden_file) + "' />");
                attrib = attrib.concat("RHS");    // READ ONLY, HIDDEN & SYSTEM
                break;
            case 0x10:
                Image = ((deleted) ? deleted_folder : folder);
//                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
//              DIRECTORY
                break;
            case 0x11:
                Image = ((deleted) ? deleted_folder : folder);
//                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("R  ");     // READ ONLY DIRECTORY
                break;
            case 0x12:
                Image = ((deleted) ? hidden_deleted_folder : hidden_folder);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_folder : hidden_folder) + "' />");
                attrib = attrib.concat("&nbsp;H");    // HIDDEN DIRECTORY
                break;
            case 0x13:
                Image = ((deleted) ? hidden_deleted_folder : hidden_folder);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_folder : hidden_folder) + "' />");
                attrib = attrib.concat("RH");    // READ ONLY & HIDDEN DIRECTORY
                break;
            case 0x14:
                Image = ((deleted) ? deleted_folder : folder);
//                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("  S");    // SYSTEM DIRECTORY
                break;
            case 0x15:
                Image = ((deleted) ? deleted_folder : folder);
//                body = body.concat("<img src='" + ((deleted) ? deleted_folder : folder) + "' />");
                attrib = attrib.concat("R S");    // READ ONLY & SYSTEM DIRECTORY
                break;
            case 0x16:
                Image = ((deleted) ? hidden_deleted_folder : hidden_folder);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_folder : hidden_folder) + "' />");
                attrib = attrib.concat(" HS");    // HIDDEN & SYSTEM DIRECTORY
                break;
            case 0x17:
                Image = ((deleted) ? hidden_deleted_folder : hidden_folder);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_folder : hidden_folder) + "' />");
                attrib = attrib.concat("RHS");    // READ ONLY, HIDDEN & SYSTEM DIRECTORY
                break;
            default:  //also case 0x20 ARCHIEVE
                Image = ((deleted) ? deleted_file : src_file);
//                body = body.concat("<img src='" + ((deleted) ? deleted_file : src_file) + "' />");
                attrib = attrib.concat("   ");
                break;

        }
//        attrib = attrib.concat("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</td>");
        return attrib;
    }

    private void recalulate(javax.swing.JTextArea a, byte ar[]) throws JAXBException {
        FileWriter fWriter = null;
        BufferedWriter writer = null;
        try {

            File file = new File("src/cache/" + title + ".dat");
            file.getParentFile().mkdirs();
            fWriter = new FileWriter(file);
            writer = new BufferedWriter(fWriter);
            StringBuilder b = new StringBuilder("\t0\t1\t2\t3\t4\t5\t6\t7\t\t8\t9\tA\tB\tC\tD\tE\tF\n");
            int j = 0;
            int old_j = 0, new_j;
            int number_of_root_sectors = 2;
            int last_byte_in_root = number_of_root_sectors*sectors_per_cluster*bytes_per_Sector;
            filelister:
            while (j < last_byte_in_root) {
                FileRecord fileRec = new FileRecord();
                String name="", size="";
                long startSector;
//                System.out.println(j);
                for(i=j;i<(j+16);i++){
                    if (i % 8 == 0) {
                        b = b.append("\t");
                    }
                    b = b.append(Utils.hex(ar[i])).append("\t");                    
                }
                b = b.append("\t\t\t");
                for(i=j;i<(j+16);i++){
                    b = b.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                }
                b = b.append("\n");
                for(i=(j+16);i<(j+32);i++){
                    if (i % 8 == 0) {
                        b = b.append("\t");
                    }
                    b = b.append(Utils.hex(ar[i])).append("\t");                    
                }
                b = b.append("\t\t\t");
                 for(i=(j+16);i<(j+32);i++){
                     b = b.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                 }
                b = b.append("\n");
                body = b.toString();
                a.setText(body);
                int attribute = Utils.hexToInt(Utils.hex(ar[i = j + 11]), "0");    //Byte 11 attribute
//                System.out.println("Attribute in recalc: "+attribute);
                switch (attribute) {
                    case 0x0F:
//               LongFileName
                        j += 32;
//                        System.out.println("Skipped: " + j);
                        continue filelister;
                    default:
                        String attrib;
//                        body = body.concat("<file>");
                        if (Utils.hexToInt(Utils.hex(ar[j]), "0") == 0xE5) {
//                                body = body.concat("<td align='left' style='color:red;'>");
//                            body = body.concat("<name>");
                            deleted = true;
                        } else {
//                                body = body.concat("<td align='left' style='color:black;'>");
//                            body = body.concat("<name>");
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
//                                        System.out.print(temp + "  ");
                                        if ((temp.equals("\u0000"))||(temp.equals("\uFFFF"))) {
                                            break;
                                        }
                                        name = name.concat(temp);
//                                        body = body.concat(temp);
                                    }
                                    for (i = j + 15; i <= (j + 25); i += 3) {
                                        temp = String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i])));
//                                        System.out.print(temp + "  ");
                                        if ((temp.equals("\u0000"))||(temp.equals("\uFFFF"))) {
                                            break;
                                        }
                                        name = name.concat(temp);
//                                        body = body.concat(temp);
                                    }
                                    for (i = j + 29; i <= (j + 31); i += 3) {
                                        temp = String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i])));
//                                        System.out.print(temp + "  ");
                                        if ((temp.equals("\u0000"))||(temp.equals("\uFFFF"))) {
                                            break;
                                        }
                                        name = name.concat(temp);
//                                        body = body.concat(temp);
                                    }
                                    j -= 32;

                                }
                                j = new_j;
//                                    body = body.concat("</td>");
//                                System.out.println("");
                                break;
                            default:
                                attrib = checkIfDeleted(attribute);
                                for (i = j; i <= (j + 10); i++) //Byte 0-10 filename
                                {
                                    name = name.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
//                                    body = body.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
//                            a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                                }
                                break;
                        }
//                        body = body.concat("</name>");

//                        body = body.concat(attrib);
                        i = j + 20;           //Byte 20-21 starting sector high order
                        //Byte 26-27 starting sector low  order
//                            a.append("@ sector " + String.format("%04X\t", Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i]), Utils.hex(ar[i = j + 26]), Utils.hex(ar[++i]), "0", "0", "0", "0")));
                 startSector = Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i]), Utils.hex(ar[i = j + 26]), Utils.hex(ar[++i]), "0", "0", "0", "0");
                        //      body = body.concat("<sector>" + String.format("%04X\t", Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i]), Utils.hex(ar[i = j + 26]), Utils.hex(ar[++i]), "0", "0", "0", "0")) + "</sector>");
                        //Bytes 28-31 file size
//                            body = body.concat("<td align='left'>" + Utils.getSize(Utils.hexToInt(Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), "0", "0", "0", "0")) + "</td>");
                        size = size.concat(Utils.getSize(Utils.hexToInt(Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), "0", "0", "0", "0")));
                  //      body = body.concat("<size>" + Utils.getSize(Utils.hexToInt(Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), "0", "0", "0", "0")) + "</size>");
                        //a.append(Utils.getSize(Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), "0", "0", "0", "0")) + "\n");
                        old_j = j;
                        fileRec.setName(name);
                        fileRec.setAttributes(attrib);
                        fileRec.setStartSector(startSector);
                        fileRec.setImage(Image);
                        fileRec.setFileSize(size);
                        fileRec.setFoundAt(j);
                        files.add(fileRec);

                        break;



                    case 0x08:
//                            body = body.concat("<tr>");
//                            body = body.concat("<td align='left' colspan='3'><b>");
//                            for (i = j; i <= (j + 10); i++) //Byte 0-10 filename
//                            {
//                                body = body.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
//                            }
                        //a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
//                            body = body.concat("&#09; VOLUME ID</b></td>");
                        //a.append("\t VOLUME ID\n");
                        break;
                }
                //increment by 32 to go to next file entry.
                j += 32;
//                    body = body.concat("</tr>");


//                body = body.concat("</file>");
            }
//                body = body.concat("</table>");
//            body = body.concat("</filelist>");

            // htmlString = htmlString.replace("$title", title);
            //  htmlString = htmlString.replace("$body", body);
//            a.appen d(body);
            writer.write(body);
            writer.close(); //make sure you close the writer object

        } catch (Exception ex) {
            Logger.getLogger(FAT32.class.getName()).log(Level.SEVERE, null, ex);
            System.err.println("Exception Occured");
        }

        FileList filelist = new FileList();
        filelist.setFile(files);
         // create JAXB context and instantiate marshaller
    JAXBContext context = JAXBContext.newInstance(FileList.class);
    Marshaller m = context.createMarshaller();
    //m.setProperty("jaxb.encoding", "UTF-16");
    m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

    // Write to System.out
   // m.marshal(filelist, System.out);

    // Write to File
    m.marshal(filelist, new File("src/cache/" + title + ".xml"));
    }

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
            //um.setProperty("jaxb.encoding", "UTF-16");
            FileList filesList = (FileList) um.unmarshal(new FileReader(cachedXML));
            if(filesList!=null)
                System.out.println("Unmarshalled");
            else
                System.err.println("Error in unmarshallling");
            files = filesList.getFile();
            listFiles(list);
            MainJFrame.re_calc.setVisible(true);
        } else {
            byte[] ar;
            ar = new byte[((int) sectors_per_FATL) * bytes_per_Sector];//16*16*100];
            Arrays.fill(ar, (byte) 0);
            address = reserved_sectors * bytes_per_Sector;
            diskAccess.seek(jumpto);
            diskAccess.read(ar);
            recalulate(a, ar);
            listFiles(list);
            diskAccess.close();
            System.out.println("closed diskAccess");
        }
    }

    public void recoverFiles(javax.swing.JList list, String path) throws FileNotFoundException {
        if(!list.isSelectionEmpty()){
//            System.out.println(list.getSelectedIndex());
//                        System.out.println(list.getSelectedValue());
       int indices[] = list.getSelectedIndices();
//        System.out.println(list.getSelectedValue());
//        System.out.println(list.getSelectedIndex());
//        System.out.println(indices.length);
//            System.out.println(files.isEmpty());
//            System.out.println(files.size());
            System.out.println("Jumpto value: "+jumpto+"\t\tAll foundAt relative to this");
               //int fileLoc =  jumpto +  file.getFoundAt();
            byte ar[] = new byte[7168];
            diskRoot = new File("\\\\.\\" + path);
            System.out.println("\\\\.\\" + path);
            diskAccess = new RandomAccessFile(diskRoot, "rwd");
            System.out.println(diskRoot.exists());
            System.out.println(diskRoot.getAbsolutePath());
//            System.out.println(jumpto+"\t"+file.getFoundAt()+"\t"+fileLoc);
//            System.out.println("max: "+diskAccess.length());
//diskAccess.read(ar);
            ByteBuffer bb = ByteBuffer.allocate(1);
            byte b = Byte.valueOf("1");
            bb.put(b);
            System.out.println(bb.toString());
        for(int k=0;k<indices.length;k++){
           try {
               System.out.println(indices[k]);
               FileRecord file = files.get(indices[k]);
               Long fileLoc = (long) jumpto + (long) file.getFoundAt();
               System.out.println("Seeking to "+jumpto);
                           diskAccess.seek(jumpto);
               System.out.println("File Pointer: "+diskAccess.getFilePointer());
               diskAccess.read(ar);
               System.out.println("Long Max " + Long.MAX_VALUE);
               System.out.println("Long Min "+ Long.MIN_VALUE);//System.out.println("File Pointer: "+diskAccess.getFilePointer());           diskAccess.seek(jumpto-235456);
               System.out.println("File Pointer: "+diskAccess.getFilePointer());
   System.out.println("Seeking to "+fileLoc);
                           diskAccess.seek(fileLoc);
               System.out.println("File Pointer: "+diskAccess.getFilePointer());
   //            diskAccess.seek(15806465);
   //         diskAccess.skipBytes(32);//file.getFoundAt());
               FileChannel fc = diskAccess.getChannel();
               System.out.println("open?"+fc.isOpen());

   //            System.out.println(diskAccess.);
   System.out.println("File Pointer: "+diskAccess.getFilePointer());
   System.out.println("File Position: "+fc.position());
   //int b = diskAccess.read();
               if (Utils.hexToInt(Utils.hex(ar[file.getFoundAt()]), "0") == 0xE5) {
                   System.out.println("Lets recover "+file.getName());
   //                diskAccess.seek(fileLoc);
                   fc.position(fileLoc);
                   System.out.println("File Position: "+fc.position());
                   fc.write(bb);
                   System.out.println("File Position: "+fc.position());
                   fc.position(fileLoc);
                   System.out.println("File Position: "+fc.position());
                   //diskAccess.write(1);
   //                diskAccess.seek(fileLoc);

                   System.out.println("File Pointer: "+diskAccess.getFilePointer());
                   for (i = 0; i <= 10; i++) //Byte 0-10 filename
                                   {
                                       System.out.print(String.valueOf(Utils.hexToText(Utils.hex(ar[file.getFoundAt()+i]))));
                                 }
               }else{
                   System.out.println("Why recover an existing file?");
                   for (i = 0; i <= 10; i++) //Byte 0-10 filename
                                   {
                                       System.out.print(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                                 }
               }
               System.out.println(file.getName()+"\t"+file.getFileSize()+"\tfrom"+file.getFoundAt());
           } catch (IOException ex) {
               ex.printStackTrace();
               Logger.getLogger(FAT32.class.getName()).log(Level.SEVERE, null, ex);
           }
        }
    }else
            System.out.println("Empty selection");
    }

    private void listFiles(final javax.swing.JList list) {

        list.setEnabled(true);
        list.setBackground(Color.white);
        list.setSelectionForeground(Color.white);
        DefaultListModel l1 = new DefaultListModel();
        for(FileRecord file:files){
                JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                java.net.URL imgUrl = getClass().getResource(file.img);
               if (imgUrl != null) {
                   panel.add(new JLabel(new ImageIcon(imgUrl)));
               }
               panel.add(new JLabel(file.name+"   "+file.filesize));
               l1.addElement(panel);
            }
        list.setModel(l1);
        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        list.setSelectedIndex(0);
        list.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                System.out.println(String.format("Selected: %s", list.getSelectedIndex()));
            }
        });
            list.setCellRenderer(new CustomCellRenderer());
    }
}