registerNodes:
	curl -X POST -d '{"nodes": ["http://localhost:5000"]}' localhost:5001/nodes/register
	curl -X POST -d '{"nodes": ["http://localhost:5001"]}' localhost:5000/nodes/register

mineBlocksonFirst:
	curl localhost:5000/mine
	curl localhost:5000/mine
	curl localhost:5000/mine

test: registerNodes mineBlocksonFirst
	# resolveSecond
	curl localhost:5001/nodes/resolve