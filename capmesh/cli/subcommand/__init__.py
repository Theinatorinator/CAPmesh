import click

from capmesh.cli.subcommand.subsubcommand import subsubcommand


@click.group()
@click.pass_context
def subcommand(
    ctx: click.Context,
) -> None:
    """
    This contains sub-subcommands
    """


subcommand.add_command(subsubcommand, name="subsub")
