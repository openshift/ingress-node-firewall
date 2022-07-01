How to Submit Patches for ingress-node-firewall
===============================================

Create github pull requests for the repo.  More details are included below.

Before You Start
----------------

Before you send patches at all, make sure that each patch makes sense.
In particular:

  - A given patch should not break anything, even if later
    patches fix the problems that it causes.  The source tree
    should still work after each patch is applied.  (This enables
    `git bisect` to work best.)

  - A patch should make one logical change.  Don't make
    multiple, logically unconnected changes to disparate
    subsystems in a single patch.

  - A patch that adds or removes user-visible features should
    also update the appropriate user documentation or manpages.

Commit Summary
-------------

The summary line of your commit should be in the following format:
`<area>: <summary>`

  - `<area>:` indicates the area of the ovn-kubernetes to which the
    change applies (often the name of a source file or a
    directory).  You may omit it if the change crosses multiple
    distinct pieces of code.

  - `<summary>` briefly describes the change.

Commit Description
------------------

The body of the commit message should start with a more thorough description of
the change.  This becomes the body of the commit message, following
the subject.  There is no need to duplicate the summary given in the
subject.

Please limit lines in the description to 79 characters in width.

The description should include:

  - The rationale for the change.

  - Design description and rationale (but this might be better
    added as code comments).

  - Testing that you performed (or testing that should be done
    but you could not for whatever reason).

  - Tags (see below).

There is no need to describe what the patch actually changed, if the
reader can see it for himself.

If the patch refers to a commit already in the ovn-kubernetes
repository, please include both the commit number and the subject of
the patch, e.g. 'commit 632d136c (ovn-k8s-overlay: Flush the IP address
of physical interface)

Tags
----

The description ends with a series of tags, written one to a line as
the last paragraph of the email.  Each tag indicates some property of
the patch in an easily machine-parseable manner.

Examples of common tags follow.

    Signed-off-by: Author Name <author.name@email.address...>

        Informally, this indicates that Author Name is the author or
        submitter of a patch and has the authority to submit it under
        the terms of the license.  The formal meaning is to agree to
        the Developer's Certificate of Origin (see below).

        If the author and submitter are different, each must sign off.
        If the patch has more than one author, all must sign off.

        Signed-off-by: Author Name <author.name@email.address...>
        Signed-off-by: Submitter Name <submitter.name@email.address...>

    Co-authored-by: Author Name <author.name@email.address...>

        Git can only record a single person as the author of a given
        patch.  In the rare event that a patch has multiple authors,
        one must be given the credit in Git and the others must be
        credited via Co-authored-by: tags.  (All co-authors must also
        sign off.)

    Acked-by: Reviewer Name <reviewer.name@email.address...>

        Reviewers will often give an Acked-by: tag to code of which
        they approve.  It is polite for the submitter to add the tag
        before posting the next version of the patch or applying the
        patch to the repository.  Quality reviewing is hard work, so
        this gives a small amount of cr
