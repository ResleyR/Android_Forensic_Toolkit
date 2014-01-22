/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Map;
import java.util.TreeMap;

/**
 *
 * @author Pranav
 */

  
 //this two classes are writen using pseudocode found in "reverse engineering of android file system"
//mounting part of sd card can i take from other projects its too difficult..



public class yaffs_obj_hdr 
{
   
   // enum yaffs_obj_type type;

    int parent_obj_id;
    int sum_no_longer_used;	/* checksum of name. No longer used */
  //  char name[YAFFS_MAX_NAME_LENGTH + 1];

    /* The following apply to all object types except for hard links */
    int yst_mode;		/* protection */

    int yst_uid;
    int yst_gid;
    int yst_atime;
    int yst_mtime;
    int yst_ctime;

    /* File size applies to files only */
    int file_size_low;

    /* Equivalent object id applies to hard links only. */
    int equiv_id;

    /* Alias is for symlinks only. */
   // YCHAR alias[YAFFS_MAX_ALIAS_LENGTH + 1];

    int yst_rdev;	/* stuff for block and char devices (major/min) */

    int win_ctime[] = new int[2];
    int win_atime[] = new int[2];
    int win_mtime[] = new int[2];

    int inband_shadowed_obj_id;
    int inband_is_shrink;

    int file_size_high;
    int reserved[] = new int[1];
    int shadows_obj;	/* This object header shadows the specified object if > 0 */

    /* is_shrink applies to object headers written when we make a hole. */
    int is_shrink;
};
//    
//    
// public class yaffs_ext_tags
// {
//    long chunk_used;	/*  Status of the chunk: used or unused */
//    long obj_id;	/* If 0 this is not used */
//    long chunk_id;	/* If 0 this is a header, else a data chunk */
//    long n_bytes;	/* Only valid for data chunks */
//
//    /* The following stuff only has meaning when we read */
//    yaffs_ECCResult yaffs_ECCResult ;
//    long block_bad;
//
//    /* YAFFS 1 stuff */
//    long is_deleted;	/* The chunk is marked deleted */
//    long serial_number;	/* Yaffs1 2-bit serial number */
//
//    /* YAFFS2 stuff */
//    long seq_number;	/* The sequence number of this block */
//
//    /* Extra info if this is an object header (YAFFS2 only) */
//
//    long extra_available;	/* Extra info available if not zero */
//    long extra_parent_id;	/* The parent object */
//    long extra_is_shrink;	/* Is it a shrink header? */
//    long extra_shadows;	/* Does this shadow another object? */
//
//    yaffs_obj_type extra_obj_type;	/* What object type? */
//    
//    long extra_equiv_id;	/* Equivalent object for a hard link */
//};
//
//}
//
// */