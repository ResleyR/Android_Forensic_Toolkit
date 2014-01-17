/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 *
 * @author Resley Rodrigues
 */
public class NTFS {
    String jump_instruction = "";       //0-2           0x00
    String file_system_ID = "";         //3-10          0x03
    int bytes_per_Sector;               //11-12         0x0B
    int sectors_per_cluster;            //13            0x0D
    int reserved_sectors;               //14-15         0x0E
    String media_descriptor;            //21            0x13
    int sectors_per_track;              //24-25         0x18
    int number_of_heads;                //26-27         0x1A
    int hidden_sectors;                 //28-31         0x1C
    long total_sectors;                 //40-47         0x28
    long location_$MFT;                 //48-55         0x30
    long location_$MFTMirr;             //56-63         0x38
    int clusters_per_file_segment;      //64-67         0x40
    int clusters_per_index_buffer;      //68            0x44
    int volume_serial_number;           //72-79         0x48         
    int checksum;                       //80-81         0x50
    int i=0;
    RandomAccessFile diskAccess;
    byte[] content = new byte[512];
    int address = 0x000000;

    public void getBPB(String path) throws FileNotFoundException, IOException {
        File diskRoot = new File("\\\\.\\" + path);
        diskAccess = new RandomAccessFile(diskRoot, "r");
        diskAccess.readFully(content);
        jump_instruction = Utils.hex(content[i++]) +Utils.hex(content[i++]) + Utils.hex(content[i++]);
        for (i = 3; i <= 10; i++) {
            file_system_ID = file_system_ID.concat(String.valueOf(Utils.hexToText(Utils.hex(content[i]))));
        }
        bytes_per_Sector = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));
        sectors_per_cluster = Utils.hexToInt(Utils.hex(content[i++]), "00");
        reserved_sectors = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));
        media_descriptor = Utils.hex(content[i = 21]);
        i = 24;
        sectors_per_track = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));
        number_of_heads = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));
        hidden_sectors = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));
        i = 40;
        total_sectors = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));
        location_$MFT = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));
        location_$MFTMirr = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]), Utils.hex(content[i++]));

    }

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
        a.append(String.format("\n%-22s\t%s","FIle System ID",file_system_ID));
        a.append(String.format("\n%-22s\t%d","Bytes per Sector",bytes_per_Sector));
        a.append(String.format("\n%-22s\t%d","Sectors per Cluster",sectors_per_cluster));
        a.append(String.format("\n%-22s\t%d","Reserved Sectors",reserved_sectors));
        a.append(String.format("\n%-22s\t%s","Media Descriptor",media_descriptor));
        a.append(String.format("\n%-22s\t%d","Sectors per Track",sectors_per_track));
        a.append(String.format("\n%-22s\t%d","Number of Heads",number_of_heads));
        a.append(String.format("\n%-22s\t%d","Hidden Sectors",hidden_sectors));
        a.append(String.format("\n%-22s\t%d","Total Sectors",total_sectors));
        a.append(String.format("\n%-22s\t\t%d","MFT Start",location_$MFT));
        a.append(String.format("\n%-22s\t%d","MFT Mirror Start",location_$MFTMirr));
    }
    
    public void readMFT(javax.swing.JTextArea a) throws IOException {
        MFT[] mft_header = new MFT[200];
        System.out.println(diskAccess.getFilePointer());
        diskAccess.seek((location_$MFT*sectors_per_cluster*bytes_per_Sector)+17408);    //skip first 16 records
        System.out.println("Max: "+total_sectors*bytes_per_Sector);
        System.out.println(diskAccess.getFilePointer());
        byte ar[] = new byte[1024];
//        diskAccess.skipBytes(2048);
        i = 0;
        while(i < mft_header.length)
        {
//            System.out.println("Offset: "+diskAccess.getFilePointer());
            mft_header[i] = new MFT();
            diskAccess.read(ar);
            mft_header[i].set_data(ar);
            mft_header[i].print_data(a);
            i++;
        }
        
    }
    
}