all:
	gcc -o rfs_filter rfs_filter.c -O2 -libverbs
clean:
	rm rfs_filter
