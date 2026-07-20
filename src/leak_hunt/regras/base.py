"""Tipos compartilhados pelas regras de detecção."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
import re


Validador = Callable[[re.Match[str], str], bool]


@dataclass(frozen=True, slots=True)
class Deteccao:
    """Correspondência encontrada por uma regra."""

    codigo: str
    tipo: str
    valor: str
    inicio: int
    fim: int
    minimo_por_arquivo: int = 1


@dataclass(frozen=True, slots=True)
class Regra:
    """Regra baseada em expressão regular e validação opcional."""

    codigo: str
    tipo: str
    padrao: re.Pattern[str]
    validador: Validador | None = None
    minimo_por_arquivo: int = 1

    def procurar(self, texto: str) -> Iterator[Deteccao]:
        """Produz as correspondências válidas encontradas no texto."""
        for correspondencia in self.padrao.finditer(texto):
            if self.validador and not self.validador(correspondencia, texto):
                continue
            yield Deteccao(
                codigo=self.codigo,
                tipo=self.tipo,
                valor=correspondencia.group(0),
                inicio=correspondencia.start(),
                fim=correspondencia.end(),
                minimo_por_arquivo=self.minimo_por_arquivo,
            )
