# Computer Security - Golf Team

## Project Workflow
Project code should be compartmentalized to a subdirectory with an
appropriate name located in the top level of the repository
(Project One = P1). This project should **NOT** be polluted with
non-code materials (presentation slides, etc). In general, copy
the sub-directories containing the skeleton code and any
associated files into the project directory (ex: P1) and make
that the initial commit on the new branch.

**EVERY** project subdirectory must include a `README.md`
describing your work and any special notes necessary for your
work to be evaluated (e.g. how to build/run your code). This
README should **NOT** be a copy paste of the provided assignment
`README.md` file for the respective CS-S18 project. Rather, this
README fulfills the report/documentation required of every
submitted project.

### (1) Starting Work
For each project, create a branch **off of master** -- run
`git status` or `git branch` to make sure your current branch
is master. If you are not on master, simply run
`git checkout master` to move to it. To create the new project
branch, run `git checkout -b BRANCH_NAME`. Name branches using
the following convention:

* Projects
  * P1, P2, P3

After your first commit on this branch, push to remote via
`git push -u origin BRANCH_NAME` and open a pull request comparing
the branch to the master base branch. Note that your pull request
is the clearest indication to your instructors that you have begun
work on a given task!

Pull Requests should be titled following this example format:
"P1 - Alpha" where "Alpha" is your team designator. Additionally,
set reviewers to `@ASRL/cs-instructors` and assign the PR to
all teammates.

### (2) Getting Help
Ping the instructors at `@ASRL/cs-instructors` via an Issue, Pull
Request, or on Keybase to notify them that you need help with your
work. Use this repository for personalized help for your team. Use
the [class repository](https://github.com/ASRL/CS-S18) for more
generalized questions/concerns.

### (3) Submitting Work
When you are ready to submit, ping the instructors that your work
is complete. The instructors will review the pull request and take
one of two actions:

* Approval
  * Your work is considered complete and graded -- you may safely merge via the green `merge` button using a "merge commit" method (should be the default)
    * Once done, run `git checkout master` and `git pull --rebase` to pull the new commits on the remote master into your local master.
* Request Changes
  * Your instructor may ask for you to correct or improve some portion of your work. Make these changes, commit/push them, and ping instructors again. This process will continue until work receives final approval.

### Miscellaneous Notes
* Use coherent/concise commit messages
* DO NOT delete project branches

