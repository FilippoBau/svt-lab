import angr
import sys

path_to_binary = "../target/crackme2"
project = angr.Project(path_to_binary)
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)

def is_successful(state):
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  return b'valid' in stdout_output  # :boolean

def should_abort(state):
  stdout_output = state.posix.dumps(sys.stdout.fileno())
  return b"Dommage, essaye encore une fois." in stdout_output  # :boolean

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
  solution_state = simulation.found[0]
  print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
  raise Exception('Could not find the solution')

#b'123456789\n'
