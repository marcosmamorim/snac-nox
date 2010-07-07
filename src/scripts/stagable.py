#!/usr/bin/python
# StaGAble - (S)cript (t)o (a)dd (G)oogle (A)nalytics (b)efore (l)ast (e)nd-tag
# By TARP, 5/24/08
# Nicira Networks
#
# Description:
# Quick hack to make sure web files use google analytics
# Intended for use in preparing nox releases
# 
# Command Line Arguments:
# Directory to convert from
# Directory to convert to
#
# Note:
# May specify the same directory twice, to convert in-place
#
# Effect:
# Takes all .html files in input directory, searches for the any
# </body> tags, and adds the contents of the file 'analytics.blip' before
# it, preserving indentation of the tag, and slightly indenting the insert.
#
# Error-checking:
# Minimal, it doesn't fail on most non-fatal problems, but prints
# warnings.  Not a fan of strange </body> tag placement, doesn't try to
# parse the html at all.
#
# TODO:
# Need better spec to proceed.  Conceivable that searching from bottom
# and only padding a single tag would be preferable, to avoid running
# into problems (if someone ever wanted to type '</body>', for example)
#

import os    # access, F_OK, listdir

# InsipiD - (I)nsert (n)umerous (s)trings (i)n-(p)lace (i)nto (D)OM
# (Based on search string, extension, directory)
def insipid(argv):
   # Magic Numbers
   extension = ".html"
   search = "</body>"
   insert_file = "analytics.blip"
   insert = open(insert_file,"r").readlines()
   indent = 2
   not_found = -1


   # Limitied Input checking
   blargv = 0  # bad location argv
   for arg in argv:
      if not os.access(arg, os.F_OK):
         print " ** Error ** %s is an invalid path" % arg
         blargv += 1
   if blargv > 0:
       print " ** Error ** %d bad path%s passed, failing" \
             % (blargv, blargv>1 and "s" or "")
       exit(1)

   if len(argv) != 2:
      #! For now, require explicit declaration of both
      # Final behavior:
      # 0: current directory
      # 1:  convert input in-place
      # 2:  input -> output conversion
      # 3+ could make up something, but nothing natural
      print " ** Error ** Must supply a input and output directory, failing"
      exit(1)
   
   input = argv[0]
   output = argv[1]
   print "Converting %s/*%s -> %s/*%s" % (input, extension, output, extension)

   for filename in os.listdir(input):
       if not filename.endswith(extension):
           continue

       # 3-line version allows us to close()
       proper = open(input +"/"+ filename,"r")
       in_text = proper.readlines()
       proper.close()

       body_count = 0
       body_bag = {}
       out_text = []
       for num in range(len(in_text)):
           line = in_text[num]

           # Check for existing instances of insert, could do better with split
           if line.find(insert[0]) is not_found:
               pass
           else:
               for k in range(1,len(insert)):
                   if in_text[num+k].find(insert[k]) is not_found:
                       break
                   if k == len(insert)-1:
                       print " ** Warning ** %s:%d-%d already contains " \
                             "the text-to-be-inserted" % (filename, num, \
                                                          num+len(insert))

           # Close body tag check:
           location = line.find(search)
           if location is not_found:
               out_text.append(line) # So close to not needing the else,
                                     # unfortunately, last line has no '\n'
           else:
               out_text.append(line[:location] + "\n")
               body_count += 1
               body_bag[num+1] = line

               # Indent insert as well
               for add in insert:
                   out_text.append(" "*(location+indent) + add)
               out_text.append(" "*location + line[location:])

               # Don't want to deal with strange end on lines twice
               if line.find(search,location+len(search)) > 0: 
                   print " ** Error ** Weird line: '%s' in %s" % \
                         (line.encode('string_escape'), filename)
                   exit(2)

       # Should just be one closing body tag
       if body_count != 1:
          print " ** Warning ** %d `</body>` tags in %s" %(body_count, filename)
          if body_count > 1:
             sorted = body_bag.keys()
             sorted.sort()
             print " ** Warning ** Lines: %s" % str(sorted)[1:-1]
             for body in sorted:
                 print " ** Warning ** [%s:%d]\t> %s" % (filename, body, \
                               body_bag[body].encode('string_escape'))

       # 3-line version allows us to close()
       proper = open(output +"/"+ filename,"w")
       proper.writelines(out_text)
       proper.close()

   print "Finished"


if __name__ == '__main__':
   import sys
   insipid(sys.argv[1:])
