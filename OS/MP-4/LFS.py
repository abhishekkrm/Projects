#!/usr/bin/python
import sys, struct
import Segment
import InodeMap

from threading import Thread, Lock, Condition, Semaphore
from Segment import SegmentManagerClass
from Disk import DiskClass
from Inode import Inode, getmaxinode, setmaxinode
from InodeMap import InodeMapClass
from FileDescriptor import FileDescriptor
from DirectoryDescriptor import DirectoryDescriptor
from Constants import FILENAMELEN
from FSE import FileSystemException
import Disk
from os.path import curdir
from numpy.distutils.fcompiler import none

def find_parent_name(path):
    parent, sep, element = path.rpartition("/")
    if parent == '':
        parent = '/'
    return parent

def find_filename(path):
    parent, sep, element = path.rpartition("/")
    return element

#takes an absolute path, iterates through the components in the name
def get_path_components(path):
    for component in path[1:].strip().split("/"):
        yield component

class LFSClass:
    def __init__(self, initdisk=True):
        pass

    # open an existing file or directory
    def open(self, path, isdir=False):
        inodenumber = self.searchfiledir(path)
        if inodenumber is None:
            raise FileSystemException("Path Does Not Exist")
        # create and return a Descriptor of the right kind
        if isdir:
            return DirectoryDescriptor(inodenumber)
        else:
            return FileDescriptor(inodenumber)

    def create(self, filename, isdir=False):
        fileinodenumber = self.searchfiledir(filename)
        if fileinodenumber is not None:
            raise FileSystemException("File Already Exists")

        # create an Inode for the file
        # Inode constructor writes the inode to disk and implicitly updates the inode map
        newinode = Inode(isdirectory=isdir)

        # now append the <filename, inode> entry to the parent directory
        parentdirname = find_parent_name(filename)
        parentdirinodenumber = self.searchfiledir(parentdirname)
        if parentdirinodenumber is None:
            raise FileSystemException("Parent Directory Does Not Exist")
        parentdirblockloc = InodeMap.inodemap.lookup(parentdirinodenumber)
        parentdirinode = Inode(str=Segment.segmentmanager.blockread(parentdirblockloc))
        self.append_directory_entry(parentdirinode, find_filename(filename), newinode)

        if isdir:
            return DirectoryDescriptor(newinode.id)
        else:
            return FileDescriptor(newinode.id)

    # return metadata about the given file
    def stat(self, pathname):
        inodenumber = self.searchfiledir(pathname)
        if inodenumber is None:
            raise FileSystemException("File or Directory Does Not Exist")

        inodeblocknumber = InodeMap.inodemap.lookup(inodenumber)
        inodeobject = Inode(str=Segment.segmentmanager.blockread(inodeblocknumber))
        return inodeobject.filesize, inodeobject.isDirectory

    # delete the given file
    def unlink(self, pathname):
        # XXX - do this tomorrow! after the meteor shower!
        filename = find_filename(pathname)
        fileinodenumber = self.searchfiledir(pathname)
        if fileinodenumber is None:
            raise FileSystemException("File Not Exists")
        parentdirname = find_parent_name(filename)
        parentdirinodenumber = self.searchfiledir(parentdirname)
        if parentdirinodenumber is None:
            raise FileSystemException("Parent Directory Does Not Exist")

        parentdirblockloc = InodeMap.inodemap.lookup(parentdirinodenumber)
        parentdirinode = Inode(str=Segment.segmentmanager.blockread(parentdirblockloc))
        parentdir = DirectoryDescriptor(parentdirinodenumber)
        dir_data =""
        for (name, inode) in parentdir.enumerate():
            if filename != name:
                dir_data += struct.pack("%dsI" % FILENAMELEN, name, inode)
        parentdirinode.filesize = parentdirinode.filesize - (FILENAMELEN + 4)
        parentdirinode.write(0,dir_data)
        pass

    # write all in memory data structures to disk
    def sync(self):
        (imap_data, generationcount) = InodeMap.inodemap.save_inode_map(getmaxinode())
        inode_imap = Inode(isdirectory=False)
        inode_imap.write(0, imap_data)
        imap_blk_loc = InodeMap.inodemap.lookup(inode_imap.id)
        Segment.segmentmanager.update_inodemap_position(imap_blk_loc, generationcount)
        Segment.segmentmanager.flush()
        pass


    # restore in memory data structures (e.g. inode map) from disk
    def restore(self):
        imlocation = Segment.segmentmanager.locate_latest_inodemap()
        iminode = Inode(str=Disk.disk.blockread(imlocation))
        imdata = iminode.read(0, 10000000)
        # restore the latest inodemap from wherever it may be on disk
        setmaxinode(InodeMap.inodemap.restore_inode_map(imdata))

    # for a given file or directory named by path,
    # return its inode number if the file or directory exists,
    # else return None
    def searchfiledir(self, path):
        # XXX - do this tomorrow! after the meteor shower!
        root_inode = 1
        path = path.strip()
        found_inode = None
        if path=="/":
            return root_inode
        cur_dir = DirectoryDescriptor(root_inode)
        path_list = []
        for components  in get_path_components(path):
            path_list.append(components)
        found = False
        while len(path_list):
            elm = path_list.pop(0)
            found = None
            for (name, inode) in cur_dir.enumerate():
                if name == elm:
                    found = True
                    found_inode = inode;
                    if len(path_list):
                        cur_dir = DirectoryDescriptor(inode)
                    break
            if found == None:
                return None
        return found_inode
        pass

    # add the new directory entry to the data blocks,
    # write the modified inode to the disk,
    # and update the inode map
    def append_directory_entry(self, dirinode, filename, newinode):
        dirinode.write(dirinode.filesize, struct.pack("%dsI" % FILENAMELEN, filename, newinode.id))

filesystem = None
