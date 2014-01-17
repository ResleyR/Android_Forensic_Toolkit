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
public class FAT12 {
//Default FAT values
    String jump_instruction = "";   //0-2
    String OEM_name = "";           //3-10
    int bytes_per_Sector;           //11-12
    int sectors_per_cluster;        //13
    int reserved_sectors;           //14-15
    int number_of_FAT_copies;       //16
    int number_of_root_directory_entries;   //17-18     0 for FAT32
    int total_sectors;              //19-20             for smaller than 32 MB
    String media_descriptor;        //21
    int sectors_per_FAT;            //22-23             0 for FAT32
    int sectors_per_track;          //24-25
    int number_of_heads;            //26-27    
    int hidden_sectors;             //28-29
                                    //30-509 Bootstrap
    String signature = "";          //510-511
    int i=0;
    RandomAccessFile diskAccess;
    byte[] content = new byte[512];
    int address = 0x000000;
    File diskRoot;

    public void getBPB(String path) throws FileNotFoundException, IOException {
        diskRoot = new File("\\\\.\\" + path);
        diskAccess = new RandomAccessFile(diskRoot, "r");
        diskAccess.readFully(content);
        
        jump_instruction = Utils.hex(content[i++]) +Utils.hex(content[i++]) + Utils.hex(content[i++]);          //0-2
        for (i = 3; i <= 10; i++) {
            OEM_name = OEM_name.concat(String.valueOf(Utils.hexToText(Utils.hex(content[i]))));                 //3-10
        }
        bytes_per_Sector = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                    //11-12
        sectors_per_cluster = Utils.hexToInt(Utils.hex(content[i++]), "00");                                    //13
        reserved_sectors = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                    //14-15
        number_of_FAT_copies = Utils.hexToInt(Utils.hex(content[i++]), "00");                                   //16
        number_of_root_directory_entries = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));    //17-18
        total_sectors = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                       //19-20
        media_descriptor = Utils.hex(content[i++]);                                                             //21
        sectors_per_FAT = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                     //22-23
        sectors_per_track = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                   //24-25
        number_of_heads = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                     //26-27
        hidden_sectors = Utils.hexToInt(Utils.hex(content[i++]), Utils.hex(content[i++]));                      //28-29
        signature = Utils.hex(content[i=510]) + Utils.hex(content[i=511]);
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
        a.append(String.format("\n%-22s\t\t%s","OEM",OEM_name));
        a.append(String.format("\n%-22s\t%d","Bytes per Sector",bytes_per_Sector));
        a.append(String.format("\n%-22s\t%d","Sectors per Cluster",sectors_per_cluster));
        a.append(String.format("\n%-22s\t%d","Reserved Sectors",reserved_sectors));
        a.append(String.format("\n%-22s\t%d","Number of FAT Copies",number_of_FAT_copies));
        a.append(String.format("\n%-22s\t%d","Root Directory Entries",number_of_root_directory_entries));
        a.append(String.format("\n%-22s\t%d","Total Sectors",total_sectors));
        a.append(String.format("\n%-22s\t%s","Media Descriptor",media_descriptor));
        a.append(String.format("\n%-22s\t%d","Sectors per FAT",sectors_per_FAT));
        a.append(String.format("\n%-22s\t%d","Sectors per Track",sectors_per_track));
        a.append(String.format("\n%-22s\t%d","Number of Heads",number_of_heads));
        a.append(String.format("\n%-22s\t%d","Hidden Sectors",hidden_sectors));
        a.append(String.format("\n%-22s\t\t%s","Signature",signature));
    }
    
    public void readFAT(javax.swing.JTextArea a) throws IOException {
        diskAccess.seek(reserved_sectors*bytes_per_Sector);
        while(diskAccess.getFilePointer()!=(total_sectors*bytes_per_Sector))
        {
            diskAccess.readFully(content);
            for(i=0;i<512;i++)
            {
               a.append(Utils.hex(content[i]));
            }
        }
        
        
    }
}
