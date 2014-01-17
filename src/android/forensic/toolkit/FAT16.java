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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.ImageIcon;
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
public class FAT16 extends FAT12 {
//Import Default FAT values from base class
//FAT16 specific values
                                    //11-27             (as before)
    long hidden_sectorsL;           //28-31
    long total_sectorsL;            //32-35
    int logical_drive_number;       //36                for use with INT 13, e.g. 0 or 0x80
                                    //37                Reserved
    int extened_signature;          //38                Extended signature (0x29)
                                    //                  Indicates that the three following fields are present.
    long serial_number;             //39-42
    String label = "";              //43-53
    String type = "";               //54-61
                                    //62-509            Bootstrap
                                    //510-511           Signature (imported)
    
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
    static ArrayList<FileRecord> files = new ArrayList<>();

    @Override
    public void getBPB(String path) throws FileNotFoundException, IOException {
        super.getBPB(path);
        //default values completed... FAT32 specific values begin
        i=28;
        hidden_sectorsL = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));   //28-31
        total_sectorsL = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));    //32-35
        logical_drive_number = Utils.hexToInt(Utils.hex(content[i++]), "00");                                                                   //36
        i++;        //37      Reserved - used to be Current Head (used by Windows NT)
        extened_signature = Utils.hexToInt(Utils.hex(content[i++]), "00");  //38  Extended signature (0x29) Indicates that the three following fields are present.
        //serial_number = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));    //67-70   Serial number of partition
        for(i=43;i<=53;i++)
           label = label.concat(String.valueOf(Utils.hexToText(Utils.hex(content[i]))));                                                        //71-81   Volume label
        for(i=54;i<=61;i++)
            type = type.concat(String.valueOf(Utils.hexToText(Utils.hex(content[i]))));                                                         //82-89   Filesystem type ("FAT32   ")
        signature = Utils.hex(content[i=510]) + Utils.hex(content[i=511]);
        System.out.println(type);
    }

    @Override
    public void printBPB(javax.swing.JTextArea a,javax.swing.JTextArea b) {
       b.append("\t\t 0\t 1\t 2\t 3\t 4\t 5\t 6\t 7\t\t 8\t 9\t A\t B\t C\t D\t E\t F");
       for (i=0; i<bytes_per_Sector; i++) {
           if (i % 16 == 0) {
               b.append(String.format("\n%07X0\t", address++));
           } else if (i % 8 == 0) {
               b.append("\t");
           }
           b.append(Utils.hex(content[i]) + "\t");
       }
        a.append(String.format("%-22s\t%s","Jump Instruction",jump_instruction));
        a.append(String.format("\n%-22s\t\t%s","OEM",OEM_name));
        a.append(String.format("\n%-22s\t%d","Bytes per Sector",bytes_per_Sector));
        a.append(String.format("\n%-22s\t%d","Sectors per Cluster",sectors_per_cluster));
        a.append(String.format("\n%-22s\t%d","Reserved Sectors",reserved_sectors));
        a.append(String.format("\n%-22s\t%d","Number of FAT Copies",number_of_FAT_copies));
        a.append(String.format("\n%-22s\t%d","Root Directory Entries",number_of_root_directory_entries));
        if(total_sectors==0)
            a.append(String.format("\n%-22s\t%d","Total Sectors",total_sectorsL));
        else
            a.append(String.format("\n%-22s\t%d","Total Sectors",total_sectors));
        a.append(String.format("\n%-22s\t%s","Media Descriptor",media_descriptor));
        a.append(String.format("\n%-22s\t%d","Sectors per FAT",sectors_per_FAT));
        a.append(String.format("\n%-22s\t%d","Sectors per Track",sectors_per_track));
        a.append(String.format("\n%-22s\t%d","Number of Heads",number_of_heads));
        a.append(String.format("\n%-22s\t%d","Hidden Sectors",hidden_sectors));
        a.append(String.format("\n%-22s\t%d","Logical Drive Number",logical_drive_number));
        a.append(String.format("\n%-22s\t%X","Extended Signature",extened_signature));
        a.append(String.format("\n%-22s\t%d","Serial Number",serial_number));
    }
    
    
    private String checkIfDeleted(int attribute) {
        String attrib = "";
        switch (attribute) {
            case 0x01:
                Image = ((deleted) ? deleted_file : src_file);
                attrib = attrib.concat("R  ");     // READ ONLY
                break;
            case 0x02:
                Image = ((deleted) ? hidden_deleted_file : hidden_file);
                attrib = attrib.concat(" H ");    // HIDDEN
                break;
            case 0x03:
                Image = ((deleted) ? hidden_deleted_file : hidden_file);
                attrib = attrib.concat("RH ");    // READ ONLY & HIDDEN
                break;
            case 0x04:
                Image = ((deleted) ? deleted_file : src_file);
                attrib = attrib.concat("  S");    // SYSTEM
                break;
            case 0x05:
                Image = ((deleted) ? deleted_file : src_file);
                attrib = attrib.concat("R S");    // READ ONLY & SYSTEM
                break;
            case 0x06:
                Image = ((deleted) ? hidden_deleted_file : hidden_file);
                attrib = attrib.concat(" HS");    // HIDDEN & SYSTEM
                break;
            case 0x07:
                Image = ((deleted) ? hidden_deleted_file : hidden_file);
                attrib = attrib.concat("RHS");    // READ ONLY, HIDDEN & SYSTEM
                break;
            case 0x10:
                Image = ((deleted) ? deleted_folder : folder);
//              DIRECTORY
                break;
            case 0x11:
                Image = ((deleted) ? deleted_folder : folder);
                attrib = attrib.concat("R  ");     // READ ONLY DIRECTORY
                break;
            case 0x12:
                Image = ((deleted) ? hidden_deleted_folder : hidden_folder);
                attrib = attrib.concat("&nbsp;H");    // HIDDEN DIRECTORY
                break;
            case 0x13:
                Image = ((deleted) ? hidden_deleted_folder : hidden_folder);
                attrib = attrib.concat("RH");    // READ ONLY & HIDDEN DIRECTORY
                break;
            case 0x14:
                Image = ((deleted) ? deleted_folder : folder);
                attrib = attrib.concat("  S");    // SYSTEM DIRECTORY
                break;
            case 0x15:
                Image = ((deleted) ? deleted_folder : folder);
                attrib = attrib.concat("R S");    // READ ONLY & SYSTEM DIRECTORY
                break;
            case 0x16:
                Image = ((deleted) ? hidden_deleted_folder : hidden_folder);
//                body = body.concat("<img src='" + ((deleted) ? hidden_deleted_folder : hidden_folder) + "' />");
                attrib = attrib.concat(" HS");    // HIDDEN & SYSTEM DIRECTORY
                break;
            case 0x17:
                Image = ((deleted) ? hidden_deleted_folder : hidden_folder);
                attrib = attrib.concat("RHS");    // READ ONLY, HIDDEN & SYSTEM DIRECTORY
                break;
            default:  //also case 0x20 ARCHIEVE
                Image = ((deleted) ? deleted_file : src_file);
                attrib = attrib.concat("   ");
                break;
        }
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
            int j = 0, old_j = 0, new_j;
            int number_of_root_sectors = 2;
            int last_byte_in_root = number_of_root_sectors * sectors_per_cluster * bytes_per_Sector;
            filelister:
            while (j < last_byte_in_root) {
                FileRecord fileRec = new FileRecord();
                String name = "", size = "";
                long startSector;
                for (i = j; i < (j + 16); i++) {
                    if (i % 8 == 0) {
                        b = b.append("\t");
                    }
                    b = b.append(Utils.hex(ar[i])).append("\t");
                }
                b = b.append("\t\t\t");
                for (i = j; i < (j + 16); i++) {
                    b = b.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                }
                b = b.append("\n");
                for (i = (j + 16); i < (j + 32); i++) {
                    if (i % 8 == 0) {
                        b = b.append("\t");
                    }
                    b = b.append(Utils.hex(ar[i])).append("\t");
                }
                b = b.append("\t\t\t");
                for (i = (j + 16); i < (j + 32); i++) {
                    b = b.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                }
                b = b.append("\n");
                body = b.toString();
                a.setText(body);
                int attribute = Utils.hexToInt(Utils.hex(ar[i = j + 11]), "0");    //Byte 11 attribute
                switch (attribute) {
                    case 0x0F:
//               LongFileName
                        j += 32;
                        continue filelister;
                    default:
                        String attrib;
                        if (Utils.hexToInt(Utils.hex(ar[j]), "0") == 0xE5) {
                            deleted = true;
                        } else {
                            deleted = false;
                        }
                        switch (Utils.hexToInt(Utils.hex(ar[j + 6]), "0")) {
                            case 0x7E:
                                new_j = j;
                                j -= 32;
                                attrib = checkIfDeleted(attribute);
                                String temp;
                                while (j > old_j) {
                                    for (i = j + 2; i <= (j + 10); i += 3) {
                                        temp = String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i])));
                                        if ((temp.equals("\u0000")) || (temp.equals("\uFFFF"))) {
                                            break;
                                        }
                                        name = name.concat(temp);
                                    }
                                    for (i = j + 15; i <= (j + 25); i += 3) {
                                        temp = String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i])));
                                        if ((temp.equals("\u0000")) || (temp.equals("\uFFFF"))) {
                                            break;
                                        }
                                        name = name.concat(temp);
                                    }
                                    for (i = j + 29; i <= (j + 31); i += 3) {
                                        temp = String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i])));
                                        if ((temp.equals("\u0000")) || (temp.equals("\uFFFF"))) {
                                            break;
                                        }
                                        name = name.concat(temp);
                                    }
                                    j -= 32;
                                }
                                j = new_j;
                                break;
                            default:
                                attrib = checkIfDeleted(attribute);
                                for (i = j; i <= (j + 10); i++) //Byte 0-10 filename
                                {
                                    name = name.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                                }
                                break;
                        }
                        i = j + 20;           //Byte 20-21 starting sector high order
                        //Byte 26-27 starting sector low  order
                        startSector = Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i]), Utils.hex(ar[i = j + 26]), Utils.hex(ar[++i]), "0", "0", "0", "0");
                        //Bytes 28-31 file size
                        size = size.concat(Utils.getSize(Utils.hexToInt(Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), Utils.hex(ar[++i]), "0", "0", "0", "0")));
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
//                      VOLUME ID
                        break;
                }
                //increment by 32 to go to next file entry.
                j += 32;
            }
            writer.write(body); //Write hex data to .dat file
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
        m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
        // Write to FileList .xml file
        m.marshal(filelist, new File("src/cache/" + title + ".xml"));
    }

    public void readFAT(javax.swing.JTextArea a, final javax.swing.JList list, Boolean forceReCalc) throws IOException, JAXBException {
        first_data_sector = reserved_sectors + (number_of_FAT_copies * sectors_per_FAT);
   //     jumpto = (int) (first_cluster - 2 + first_data_sector) * bytes_per_Sector;
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
            ar = new byte[((int) sectors_per_FAT) * bytes_per_Sector];//16*16*100];
            Arrays.fill(ar, (byte) 0);
            address = reserved_sectors * bytes_per_Sector;
            diskAccess.seek(jumpto);
            diskAccess.read(ar);
            recalulate(a, ar);
            listFiles(list);
        }
        diskAccess.close();
        System.out.println("closed diskAccess");
    }

    
    @Override
    public void readFAT(javax.swing.JTextArea a) throws IOException {
        diskAccess.seek(reserved_sectors*bytes_per_Sector);
        while(diskAccess.getFilePointer()!=(total_sectorsL*bytes_per_Sector))
        {
            diskAccess.readFully(content);
            for(i=0;i<512;i++)
            {
               a.append(Utils.hex(content[i]));
            }
        }
        
        
    }
 private void listFiles(final javax.swing.JList list) {

        list.setEnabled(true);
        list.setBackground(Color.white);
        list.setSelectionForeground(Color.white);
        DefaultListModel l1 = new DefaultListModel();
        for (FileRecord file : files) {
            JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            java.net.URL imgUrl = getClass().getResource(file.img);
            if (imgUrl != null) {
                panel.add(new JLabel(new ImageIcon(imgUrl)));
            }
            panel.add(new JLabel(file.name + "   " + file.filesize));
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
