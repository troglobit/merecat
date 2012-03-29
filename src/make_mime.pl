#!/usr/bin/perl

#Run this on developer side, whenever you update
#your mime encodings, or mime types.

open(ENCODINGS, '<', "mime_encodings.txt");
@encoding=<ENCODINGS>;
close(ENCODINGS);

open(ENCHEADER, '>', "mime_encodings.h");
foreach (@encoding)
{
	chomp($_);
	@element = split(/\t+/,$_);
	next if $element[0] =~ /#/ ;
	next if $element[1] =~ /#/ ;
	next if length($element[0]) == 0 || length($element[1]) == 0 ;
	print ENCHEADER '{ "', $element[0], '", 0, "', $element[1], '", 0 },', "\n";
}
close(ENCHEADER);


open(TYPES, '<', "mime_types.txt");
@type=<TYPES>;
close(TYPES);

open(TYPEHEADER, '>', "mime_types.h");
foreach (@type)
{
	chomp($_);
	@element = split(/\t+/,$_);
	next if $element[0] =~ /#/ ;
	next if $element[1] =~ /#/ ;
	next if length($element[0]) == 0 || length($element[1]) == 0 ;
	print TYPEHEADER '{ "', $element[0], '", 0, "', $element[1], '", 0 },', "\n";
}
close(TYPEHEADER);
