$(document).on("click", "#btnagregar", function(){
    $("#txtnomproducto").val("");
    $("#txtpreciounit").val("");
    $("#hddcodprod").val("0");
    $("#cbocategoria").empty();
    $("#cboproveedor").empty();
    $("#switchproducto" ).hide();
    $("#chkdescontinuado").prop("checked", false);
    listarCboCategoriasProveedores(0,0);
    $("#modalNuevo").modal("show");
});

$(document).on("click", ".btnactualizar", function(){
    $("#txtnomproducto").val($(this).attr("data-prodname"));
    $("#txtpreciounit").val($(this).attr("data-produnit"));
    $("#hddcodprod").val($(this).attr("data-prodcod"));
    $("#cbocategoria").empty();
    $("#cboproveedor").empty();
    listarCboCategoriasProveedores($(this).attr("data-prodcateg"), $(this).attr("data-prodprov"));
    $("#switchproducto" ).show();
    console.log($(this).attr("data-descontinuado"));
    if($(this).attr("data-descontinuado") === "true"){
        $("#chkdescontinuado").prop("checked", true);
    }else
        $("#chkdescontinuado").prop("checked", false);
    $("#modalNuevo").modal("show");
});

$(document).on("click", "#btnguardar", function(){
    $.ajax({
        type: "POST",
        url: "/product/guardar",
        contentType: "application/json",
        data: JSON.stringify({
            productid: $("#hddcodprod").val(),
            productname: $("#txtnomproducto").val(),
            unitprice: $("#txtpreciounit").val(),
            categoryid: $("#cbocategoria").val(),
            supplierid: $("#cboproveedor").val(),
            discontinued: $('#chkdescontinuado').prop('checked')
        }),
        success: function(resultado){
            if(resultado.respuesta){
                listarProductos();
            }
            alert(resultado.mensaje);
        }
    });
    $("#modalNuevo").modal("hide");
});

function listarCboCategoriasProveedores(idcategoria, idproveedor){
    $.ajax({
        type: "GET",
        url: "/category/listar",
        dataType: "json",
        success: function(resultado){
            $.each(resultado, function(index, value){
                $("#cbocategoria").append(
                    `<option value="${value.categoryid}">${value.categoryname}</option>`
                )
            });
            if(idcategoria > 0){
                $("#cbocategoria").val(idcategoria);
            }
            $.ajax({
                    type: "GET",
                    url: "/supplier/listar",
                    dataType: "json",
                    success: function(resultado){
                        $.each(resultado, function(index, value){
                            $("#cboproveedor").append(
                                `<option value="${value.supplierid}">${value.companyname}</option>`
                            )
                        });
                        if(idproveedor > 0){
                            $("#cboproveedor").val(idproveedor);
                        }
                    }
                })
        }
    });
}

function listarProductos(){
    $.ajax({
        type: "GET",
        url: "/product/listar",
        dataType: "json",
        success: function(resultado){
            $("#tblproducto > tbody").html("");
            $.each(resultado, function(index, value){
                $("#tblproducto > tbody").append("<tr>"+
                    "<td>"+value.productid+"</td>"+
                    "<td>"+value.productname+"</td>"+
                    "<td>"+value.unitprice+"</td>"+
                    "<td>"+value.categories.categoryname+"</td>"+
                    "<td>"+value.suppliers.companyname+"</td>"+
                    "<td>"+
                        "<button type='button' class='btn btn-info btnactualizar'"+
                                     "data-prodcod='"+value.productid+"'"+
                                     "data-prodname='"+value.productname+"'"+
                                     "data-produnit='"+value.unitprice+"'"+
                                     "data-prodcateg='"+value.categories.categoryid+"'"+
                                     "data-prodprov='"+value.suppliers.supplierid+"'"+
                                     "data-descontinuado='"+value.discontinued+"'"+
                                     "><i class='fas fa-edit'></i></button>"+
                    "</td></tr>");
            })
        }
    })
}