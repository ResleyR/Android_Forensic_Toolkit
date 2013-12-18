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
        for(i=64;i<=61;i++)
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
        a.append(String.format("\n%-22s\t%d","Sectors per FAT",sectors_per_FAT));
        a.append(String.format("\n%-22s\t%d","Sectors per Track",sectors_per_track));
        a.append(String.format("\n%-22s\t%d","Number of Heads",number_of_heads));
        a.append(String.format("\n%-22s\t%d","Hidden Sectors",hidden_sectors));
        a.append(String.format("\n%-22s\t%d","Logical Drive Number",logical_drive_number));
        a.append(String.format("\n%-22s\t%X","Extended Signature",extened_signature));
        a.append(String.format("\n%-22s\t%d","Serial Number",serial_number));
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
}