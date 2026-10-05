import click
from click.testing import CliRunner
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# This is the exact code added to cli.py
@click.command(name="eval-nxtwave")
@click.argument("target", type=click.Path())
@click.option("--rules-dir", type=click.Path(), required=False, help="Path to custom rules directory")
@click.pass_context
def eval_nxtwave(ctx: click.Context, target: str, rules_dir: Optional[str]) -> None:
    """Dedicated evaluation command for student AI project analysis."""
    logger.info(f"NxtWave AutoEval scan started on target path: {target}")
    if rules_dir:
        logger.info(f"Using custom rules from: {rules_dir}")
    # TODO: Pass context and arguments to downstream scanning routines

@click.group()
def cli():
    pass

cli.add_command(eval_nxtwave)

if __name__ == '__main__':
    runner = CliRunner()

    print("=== Testing Help Command ===")
    result = runner.invoke(cli, ['eval-nxtwave', '--help'])
    print(result.output)

    print("=== Testing Command Execution ===")
    result = runner.invoke(cli, ['eval-nxtwave', 'student_project_dir', '--rules-dir', 'nxtwave_rules'])
    print(result.output)
