/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;
/**
 *
 * @author Resley Rodrigues
 */
public class MFT {
    
 //   int flag;       //at byte 21
  //  int Length of File Name; //1 byte
    
    String File_Identifier = "";     //4 bytes               0
    int Offset_to_update_sequence;//2 bytes             4
    int Size_of_update_sequence;    //2 bytes           6
    int $LogFile_Sequence_Number;   //8 bytes           8
    int Sequence_Number;            //2 bytes           16
    int Reference_Count;            //2 bytes           18
    int Offset_to_Update_Sequence_Array;//2 bytes       20
    int Flags;                      //2 bytes           22
    int Real_size_of_the_FILE_record;//4 bytes          24
    int allocated_size_of_the_FILE_record;//4 bytes     28
    int File_reference_to_the_base_FILE_record; //8 bytes32
    int Next_Attribute_Id;          //2 bytes           40
        
    //If Flags field has bit 1 set, it means that file is in-use. Zero means it is deleted.
    
    //Starting from 0x48, we have Standard Information Attribute (second bold section):
    int File_Creation_Time;         //8 bytes           72
    int File_Last_Modification_Time;//8 bytes           80
    int File_Last_Modification_Time_for_File_Record;//8 bytes   88
    int File_Access_Time_for_File_Record;//8 bytes      96

    
    //Following standard attribute header,
    //we have File Name Attribute belonging to DOS name space,
    //short file names, (offset 0xA8)
    //and again following standard attribute header,
    //we have File Name Attribute belonging to Win32 name space,
    //long file names, (offset 0x120):
    
    int File_Reference_to_the_Parent_Directory; //8 bytes       288
    int File_Modification_Times;                //32 bytes      296
    long Allocated_Size_of_the_File;            //8 bytes       328
    long Real_Size_of_the_File;                 //8 bytes       336
    int FlagsL;                                 //8 bytes       344
    int Length_of_File_Name;                    //1 byte        352
    int File_Name_Space;                        //1 byte        353
    String File_Name = "";                      //Length_of_File_Name * 2 bytes 354
    
    //we can extract file name, File Creation and
    //Modification times, and Parent Directory Record number.
    
    //Starting from offset 0x188, there is a non-resident Data attribute.
    
    int Attribute_Type;                 //4 bytes (e.g. 0x80)
    int Length_including_header;        //4 bytes
    int Non_resident_flag;              //1 byte
    int Name_length;                    //1 byte
    int Offset_to_the_Name;             //2 bytes
    int FlagsNR;                          //2 bytes
    int Attribute_Id;                   //2 bytes
    int Starting_VCN;                   //8 bytes
    int Last_VCN;                       //8 bytes
    int Offset_to_the_Data_Runs;        //2 bytes
    int Compression_Unit_Size;          //2 bytes
    int Padding;                        //4 bytes
    int Allocated_size_of_the_attribute;//8 bytes
    int Real_size_of_the_attribute;     //8 bytes
    int Initialized_data_size_of_the_stream;    //8 bytes

    //Data_Runs_...
    
    
    public void set_data(byte[] ar){
        int i;
        int j=242;
        for(i=0;i<4;i++)
            File_Identifier = File_Identifier.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
        Flags = Utils.hexToInt(Utils.hex(ar[22]), Utils.hex(ar[23]));
        Real_Size_of_the_File = Utils.hexToInt(Utils.hex(ar[217]), Utils.hex(ar[218]), Utils.hex(ar[219]), Utils.hex(ar[220]), Utils.hex(ar[221]), Utils.hex(ar[222]), Utils.hex(ar[223]), Utils.hex(ar[224]));
        Name_length = Utils.hexToInt(Utils.hex(ar[240]),"0");
        System.out.println("Name length: "+Utils.hex(ar[240]));
        for(i=0;i<=(Name_length*2);i++){
           File_Name = File_Name.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i+j]))));
        }
    }
    
    public void print_data(javax.swing.JTextArea a){
        a.append(File_Identifier + "\t\t" + Flags + "\t\t" + Name_length + "\t\t" + File_Name +"\t\t"+Real_Size_of_the_File+"\n");
    }
    
}
