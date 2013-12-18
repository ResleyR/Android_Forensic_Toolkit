/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import javax.swing.JFrame;

/**
 *
 * @author Resley Rodrigues
 */
public class FAT32 extends FAT12{
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

    @Override
    public void getBPB(String path) throws FileNotFoundException, IOException {
        super.getBPB(path);
        //default values completed... FAT32 specific values begin
        i=28;
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
        //serial_number = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));    //67-70   Serial number of partition
        for(i=71;i<=81;i++)
           label = label.concat(String.valueOf(Utils.hexToText(Utils.hex(content[i]))));                                                        //71-81   Volume label
        for(i=82;i<=89;i++)
            type = type.concat(String.valueOf(Utils.hexToText(Utils.hex(content[i]))));                                                         //82-89   Filesystem type ("FAT32   ")
        signature = Utils.hex(content[i=510]) + Utils.hex(content[i=511]);
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
        if(sectors_per_FAT==0)
            a.append(String.format("\n%-22s\t%d","Sectors per FAT",sectors_per_FATL));
        else
            a.append(String.format("\n%-22s\t%d","Sectors per FAT",sectors_per_FAT));
        a.append(String.format("\n%-22s\t%d","Sectors per Track",sectors_per_track));
        a.append(String.format("\n%-22s\t%d","Number of Heads",number_of_heads));
        if(hidden_sectors==0)
            a.append(String.format("\n%-22s\t%d","Hidden Sectors",hidden_sectorsL));
        else
            a.append(String.format("\n%-22s\t%d","Hidden Sectors",hidden_sectors));
        a.append(String.format("\n%-22s\t%d","FAT Mirroring disabled",mirror_flags));
        a.append(String.format("\n%-22s\t%d","FileSystem Version",fs_version));
        a.append(String.format("\n%-22s\t%d","First Cluster Location",first_cluster));
        a.append(String.format("\n%-22s\t%d","FileSystem Info Sector",fs_info));
        a.append(String.format("\n%-22s\t%d","Backup BootSector",backup_bootsector));
        a.append(String.format("\n%-22s\t%d","Logical Drive Number",logical_drive_number));
        a.append(String.format("\n%-22s\t%X","Extended Signature",extened_signature));
        a.append(String.format("\n%-22s\t%d","Serial Number",serial_number));
        a.append(String.format("\n%-22s\t\t%s","Signature",signature));
    }
    
    @Override
        public void readFAT(javax.swing.JTextArea a) throws IOException {
        byte[] ar;
        
            System.out.println(Integer.MAX_VALUE);
            System.out.println("4294967295");
        first_data_sector = reserved_sectors + (number_of_FAT_copies * sectors_per_FATL);
ar=new byte[((int)sectors_per_FATL)*bytes_per_Sector];//16*16*100];
        Arrays.fill(ar,(byte)0);
        int jumpto = (int) (first_cluster - 2 + first_data_sector)*bytes_per_Sector;
        address = reserved_sectors*bytes_per_Sector;
        diskAccess.seek(jumpto);
            System.out.println(diskAccess.getFilePointer());
        diskAccess.read(ar);
        /*for(i=0;i<ar.length;i++)
            System.out.println(ar[i]);
        *//*
        win=new JFrame();
        
        win.getContentPane().add(new JHexEditor(ar,address));
        win.pack();
        a.setContentPane(win.getContentPane());
        a.show(); */
//        System.out.println("Start: "+reserved_sectors*bytes_per_Sector);
        int CAPACITY =  (int) (total_sectors - (reserved_sectors + (number_of_FAT_copies * sectors_per_FATL) + first_cluster));

//        System.out.println("End  : "+ CAPACITY);
//        System.out.println("Interger MAX: "+Integer.MAX_VALUE);
//        System.out.println("File pointer at " + diskAccess.getFilePointer());
//        diskAccess.seek(reserved_sectors * bytes_per_Sector);
//        System.out.println("File pointer at " + diskAccess.getFilePointer());
            int j = 0;
            int old_j=0 ,new_j;
            filelister:
            while(j < 40960){
                    System.out.println(j);
        int attribute = Utils.hexToInt(Utils.hex(ar[i=j+11]), "0");    //Byte 11 attribute
        switch(attribute){
            case 0x01:  a.append("\t READ ONLY\n");
                        break;
            case 0x02:  a.append("\t HIDDEN\n");
                        break;
            case 0x04:  a.append("\t SYSTEM\n");
                        break;
            case 0x08:  for(i=j;i<=(j+10);i++)          //Byte 0-10 filename
                            a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                        a.append("\t VOLUME ID\n");
                        break;
            case 0x16:  System.err.println(Utils.hexToInt(Utils.hex(ar[j+6]), "0"));
                switch (Utils.hexToInt(Utils.hex(ar[j+6]), "0")) {
                    case 0x7E:
                        new_j = j;
                         j -= 32;
                        if(Utils.hexToInt(Utils.hex(ar[j]), "0")==0xE5)
                            a.append("<font color='red'>DELETED\t");
                        else
                            a.append("<font color='black'>");
                        while (j > old_j) {
                            for (i = j + 2; i <= (j + 10); i += 3) {
                                a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i]))));
                            }
                            for (i = j + 15; i <= (j + 25); i += 3) {
                                a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i]))));
                            }
                            for (i = j + 29; i <= (j + 31); i += 3) {
                                a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i]))));
                            }
                            j -= 32;
                        }
                        a.append("</font>");
                        j = new_j;
                        break;
                    default:
                        for (i = j; i <= (j + 10); i++) //Byte 0-10 filename
                        {
                            a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                        }
                        break;

                }

                a.append("\t DIRECTORY\n");
                        break;
            case 0x20:
                System.err.println(Utils.hexToInt(Utils.hex(ar[j+6]), "0"));
                switch (Utils.hexToInt(Utils.hex(ar[j+6]), "0")) {
                    case 0x7E:
                        new_j = j;
                         j -= 32;
                        if(Utils.hexToInt(Utils.hex(ar[j]), "0")==0xE5)
                            a.append("DELETED\t");
                        while (j > old_j) {
                            for (i = j + 2; i <= (j + 10); i += 3) {
                                a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i]))));
                            }
                            for (i = j + 15; i <= (j + 25); i += 3) {
                                a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i]))));
                            }
                            for (i = j + 29; i <= (j + 31); i += 3) {
                                a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]) + Utils.hex(ar[--i]))));
                            }
                            j -= 32;
                        }
                        j = new_j;
                        break;
                    default:
                        for (i = j; i <= (j + 10); i++) //Byte 0-10 filename
                        {
                            a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
                        }
                        break;

                }

                a.append("\t ARCHIVE\t");
                i = j + 20;           //Byte 20-21 starting sector high order 
                //Byte 26-27 starting sector low  order 
                a.append("@ sector " + String.valueOf(Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i += 5]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), "0", "0", "0", "0")) + "\t ");
                //Bytes 28-31 file size
                a.append(Utils.getSize(Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), "0", "0", "0", "0")) + "\n");
                old_j = j;
                        break;
            case 0x0F:  
//                a.append("\t LFN\t");
                        
//                        for(i=j+2;i<=(j+10);i+=3)
//                            a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i])+Utils.hex(ar[--i]))));
//                        for(i=j+15;i<=(j+25);i+=3)
//                            a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i])+Utils.hex(ar[--i]))));
//                        for(i=j+29;i<=(j+31);i+=3)
//                            a.append(String.valueOf(Utils.hexToText(Utils.hex(ar[i])+Utils.hex(ar[--i]))));
//                        a.append("\n");
                System.out.println("Skipped: "+j);
                        //j+=32;
                        break;
            default: a.append("\t "+attribute+"\n");
                        break;
        }

//                System.out.println("@ sector  "+ String.valueOf(Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i+=5]), Utils.hex(ar[i++]), Utils.hex(ar[i++])))+"\t ");
//       System.out.println(String.valueOf(Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++])))+" bytes\n");
        
        
            //increment by 32 to go to next file entry.
            j+=32;
            //System.out.println(String.format("%04X", Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i++]))));
            }
        
//        i = 0;
//        content = new byte[16384];
//        a.setText("");
//        a.append("\t\t 0\t 1\t 2\t 3\t 4\t 5\t 6\t 7\t\t 8\t 9\t A\t B\t C\t D\t E\t F");
//        while(diskAccess.getFilePointer()<CAPACITY)
//        {
//            diskAccess.read(content);
//           System.out.println("@ "+diskAccess.getFilePointer());
//           for(i=0;i<16384;i++){
//           if (i % 16 == 0) {
//               a.append(String.format("\n%07X\t", address));
//               System.out.print(String.format("\n%07X\t", address));
//               address+=16;
//           } else if (i % 8 == 0) {
//               System.out.print("\t");
//               a.append("\t");
//           }
//           a.append(Utils.hex(ar[i])+"\t");
//               System.out.print(Utils.hex(ar[i])+"\t");
//           }
////            try {
////                Utils.hexForArray(content, a, address++);
////            } catch (EncodingAlgorithmException ex) {
////                Logger.getLogger(FAT32.class.getName()).log(Level.SEVERE, null, ex);
////            }
//           i++;
//        }
//        
//        
//        FileChannel inChannel = diskAccess.getChannel();
//        ByteBuffer buffer = ByteBuffer.allocate(CAPACITY);
//        int bytesRead = inChannel.read(buffer);
//        buffer.flip();
//        i = 0;
//        a.append("\t\t 0\t 1\t 2\t 3\t 4\t 5\t 6\t 7\t\t 8\t 9\t A\t B\t C\t D\t E\t F");
//        while (buffer.hasRemaining())
//        {
//           System.out.println("@ "+buffer.position());
//           if (i % 16 == 0) {
//               a.append(String.format("\n%07X0\t", address++));
//           } else if (i % 8 == 0) {
//               a.append("\t");
//           }
//           a.append(Utils.hex(buffer.get()) + "\t");
//           i++;
//        }
//        buffer.clear();
//        bytesRead = inChannel.read(buffer);
//        diskAccess.close();
//        
    }
}